// See LICENSE for license details.

#include "cachesim.h"
#include "common.h"
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <vector>

cache_sim_t::cache_sim_t(size_t _sets, size_t _ways, size_t _linesz, const char* _name, char policy)
: sets(_sets), ways(_ways), linesz(_linesz), policy(policy), name(_name), log(false)
{
  init();
}

static void help()
{
  std::cerr << "Cache configurations must be of the form" << std::endl;
  std::cerr << "  sets:ways:blocksize" << std::endl;
  std::cerr << "where sets, ways, and blocksize are positive integers, with" << std::endl;
  std::cerr << "sets and blocksize both powers of two and blocksize at least 8." << std::endl;
  exit(1);
}

cache_sim_t* cache_sim_t::construct(const char* config, const char* name)
{
  const char* wp = strchr(config, ':');
  if (!wp++) help();
  const char* bp = strchr(wp, ':');
  if (!bp++) help();
  const char* policyp = strchr(bp, ':'); // parse policy option
  if (!policyp++) help();

  size_t sets = atoi(std::string(config, wp).c_str());
  size_t ways = atoi(std::string(wp, bp).c_str());
  size_t linesz = atoi(std::string(bp, policyp).c_str());
  char policy = *policyp;
  if (policy != 'R' && policy != 'L' && policy != 'F') // check policy option and set default if invalid
    policy = 'R';

  // if (ways > 4 /* empirical */ && sets == 1)
  //   return new fa_cache_sim_t(ways, linesz, name, policy);
  return new cache_sim_t(sets, ways, linesz, name, policy);
}

void cache_sim_t::init()
{
  if(sets == 0 || (sets & (sets-1)))
    help();
  if(linesz < 8 || (linesz & (linesz-1)))
    help();

  idx_shift = 0;
  for (size_t x = linesz; x>1; x >>= 1)
    idx_shift++;

  tags = new uint64_t[sets*ways]();
  tag_table = new std::vector<uint64_t>[sets](); // initialize tag table
  for(size_t i = 0; i < sets; i++)
    tag_table[i] = std::vector<uint64_t>(ways);
  read_accesses = 0;
  read_misses = 0;
  bytes_read = 0;
  write_accesses = 0;
  write_misses = 0;
  bytes_written = 0;
  writebacks = 0;

  miss_handler = NULL;
}

cache_sim_t::cache_sim_t(const cache_sim_t& rhs)
 : sets(rhs.sets), ways(rhs.ways), linesz(rhs.linesz),
   idx_shift(rhs.idx_shift), policy(rhs.policy), name(rhs.name), log(false)
{
  tags = new uint64_t[sets*ways];
  memcpy(tags, rhs.tags, sets*ways*sizeof(uint64_t));
}

cache_sim_t::~cache_sim_t()
{
  print_stats();
  delete [] tags;
  delete [] tag_table;
}

void cache_sim_t::print_stats()
{
  if(read_accesses + write_accesses == 0)
    return;

  float mr = 100.0f*(read_misses+write_misses)/(read_accesses+write_accesses);

  std::cout << std::setprecision(3) << std::fixed;
  std::cout << name << " ";
  std::cout << "Bytes Read:            " << bytes_read << std::endl;
  std::cout << name << " ";
  std::cout << "Bytes Written:         " << bytes_written << std::endl;
  std::cout << name << " ";
  std::cout << "Read Accesses:         " << read_accesses << std::endl;
  std::cout << name << " ";
  std::cout << "Write Accesses:        " << write_accesses << std::endl;
  std::cout << name << " ";
  std::cout << "Read Misses:           " << read_misses << std::endl;
  std::cout << name << " ";
  std::cout << "Write Misses:          " << write_misses << std::endl;
  std::cout << name << " ";
  std::cout << "Writebacks:            " << writebacks << std::endl;
  std::cout << name << " ";
  std::cout << "Miss Rate:             " << mr << '%' << std::endl;
}

uint64_t* cache_sim_t::check_tag(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t tag = (addr >> idx_shift) | VALID;

  // search tag table for tag
  for (size_t i = 0; i < ways; i++)
  {
    auto it = find(tag_table[idx].begin(), tag_table[idx].end(), tag);
    if (it != tag_table[idx].end())
    {
      return &*it;
    }
  }

  return NULL;
}

uint64_t cache_sim_t::victimize(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t way = lfsr.next() % ways;
  // uint64_t victim = tags[idx*ways + way];
  // tags[idx*ways + way] = (addr >> idx_shift) | VALID;
  uint64_t victim = tag_table[idx][way]; // select random tag in same set in tag table for Random policy

  if (policy == 'F' || policy == 'L') // if FIFO or LRU, update tag table
  {
    if (tag_table[idx].size() == ways) // if set is full, victimize first tag in set
    {
      victim = tag_table[idx].front();
      tag_table[idx].erase(tag_table[idx].begin());
    }
    else // if set is not full, victimize nothing
    {
      victim = 0;
    }
    tag_table[idx].push_back(addr >> idx_shift | VALID); // push new tag to back of set
  }
  else // if Random, replace victimized tag with a new tag 
  {
    tag_table[idx][way] = (addr >> idx_shift) | VALID;
  }
  return victim;
}

void cache_sim_t::access(uint64_t addr, size_t bytes, bool store)
{
  store ? write_accesses++ : read_accesses++;
  (store ? bytes_written : bytes_read) += bytes;

  uint64_t* hit_way = check_tag(addr);
  if (likely(hit_way != NULL)) // cache hit
  {
    if (policy == 'L') // if LRU, find and erase "hit tag" and then push back to update LRU
    {
      size_t idx = (addr >> idx_shift) & (sets-1);
      auto it = find(tag_table[idx].begin(), tag_table[idx].end(), *hit_way);
      tag_table[idx].erase(it);
      tag_table[idx].push_back(*hit_way);
    }
    if (store)
      *hit_way |= DIRTY;
    return;
  }

// cache miss
  store ? write_misses++ : read_misses++;
  if (log)
  {
    std::cerr << name << " "
              << (store ? "write" : "read") << " miss 0x"
              << std::hex << addr << std::endl;
  }

  uint64_t victim = victimize(addr);

  if ((victim & (VALID | DIRTY)) == (VALID | DIRTY)) // if dirty and valid, write back
  {
    uint64_t dirty_addr = (victim & ~(VALID | DIRTY)) << idx_shift;
    if (miss_handler)
      miss_handler->access(dirty_addr, linesz, true);
    writebacks++;
  }

  if (miss_handler) // if invalid or clean, read from next level
    miss_handler->access(addr & ~(linesz-1), linesz, false);

  if (store)
    *check_tag(addr) |= DIRTY;
}

fa_cache_sim_t::fa_cache_sim_t(size_t ways, size_t linesz, const char* name, char policy)
  : cache_sim_t(1, ways, linesz, name, policy)
{
}

uint64_t* fa_cache_sim_t::check_tag(uint64_t addr)
{
  auto it = tags.find(addr >> idx_shift);
  return it == tags.end() ? NULL : &it->second;
}

uint64_t fa_cache_sim_t::victimize(uint64_t addr)
{
  uint64_t old_tag = 0;
  if (tags.size() == ways)
  {
    auto it = tags.begin();
    std::advance(it, lfsr.next() % ways);
    old_tag = it->second;
    tags.erase(it);
  }
  tags[addr >> idx_shift] = (addr >> idx_shift) | VALID;
  return old_tag;
}

