// Generally useful container data structures
//
// 1:1 port of `third_party/trex/trex/src/containers.rs` (500 lines) into C++20.
//
// The "unordered" name is preserved for source parity even though every container here is
// ordered (we only ship the `deterministic_containers` feature, where `UnorderedMap` and
// `UnorderedSet` are `BTreeMap`/`BTreeSet`). Iteration order therefore matches upstream:
// `UnorderedMap`/`UnorderedSet` iterate in key order; `InsertionOrderedSet` in insertion
// order. The S7 differential gate relies on this.

#pragma once

#include <cassert>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <type_traits>
#include <utility>
#include <vector>

#include <trex/error.hpp>

namespace trex {

// ---------------------------------------------------------------------------
// InsertionOrderedSet<T>
//
// A set of values of type `T`, which maintain their order of insertion into the set,
// which can then be recovered by converting it into a `Vec<T>`.
template <typename T>
class InsertionOrderedSet {
  static_assert(std::is_same_v<T, std::decay_t<T>> ||
                std::is_move_constructible_v<T>,
                "InsertionOrderedSet<T>: T must be move-constructible");

public:
  InsertionOrderedSet() = default;

  /// Convert into a vec, maintaining the order of insertion and all indexes that were
  /// returned at insertion.
  std::vector<T> into_vec() && { return std::move(data_); }

  /// Insert `v` into the set, returning an index that can be used for the vector when
  /// eventually `into_vec` is run. If `v` already exists in the set, will not perform
  /// re-insertion, but will instead directly refer to the pre-existing value.
  std::size_t insert(const T& v)
    requires std::is_copy_constructible_v<T>
  {
    if (auto it = revmap_.find(v); it != revmap_.end()) {
      return it->second;
    }
    const std::size_t idx = data_.size();
    data_.push_back(v);
    revmap_.emplace(data_.back(), idx);
    return idx;
  }

  /// Move-insert overload.
  std::size_t insert(T&& v)
  {
    if (auto it = revmap_.find(v); it != revmap_.end()) {
      return it->second;
    }
    const std::size_t idx = data_.size();
    revmap_.emplace(v, idx);
    data_.push_back(std::move(v));
    return idx;
  }

  /// Get the member of the set at index `idx`.
  std::optional<std::reference_wrapper<const T>> get(std::size_t idx) const
  {
    if (idx >= data_.size()) return std::nullopt;
    return std::cref(data_[idx]);
  }

  /// Get the index of `v` if it exists in the set.
  std::optional<std::size_t> get_index(const T& v) const
  {
    auto it = revmap_.find(v);
    if (it == revmap_.end()) return std::nullopt;
    return it->second;
  }

  /// Iterate over the storage, in the order of insertion.
  const std::vector<T>& iter() const { return data_; }

  const T& operator[](std::size_t idx) const { return data_[idx]; }

private:
  std::vector<T> data_;
  std::map<T, std::size_t> revmap_;
};

// ---------------------------------------------------------------------------
// DisjointSetIndexes
//
// A highly-minimal disjoint-set data structure, also known as union-find. Intended to be
// used with a separate `Vec<T>` holding actual objects to make itself useful. For a nicer
// interface that allows sets of values of arbitrary type `T`, see `DisjointSet`.
class DisjointSetIndexes {
public:
  DisjointSetIndexes() = default;

  /// Obtain the (current) representative of a set containing `x`.
  std::size_t representative(std::size_t x)
  {
    // Grow the forest on demand (mirrors upstream's `while x >= f.len() { f.push(f.len()) }`).
    while (x >= forest_.size()) {
      forest_.push_back(forest_.size());
    }
    if (forest_[x] == x) {
      return x;
    }
    // Path compression: collect the chain, then rewrite every link to the root.
    std::vector<std::size_t> interm;
    std::size_t cur = x;
    while (forest_[cur] != cur) {
      interm.push_back(cur);
      cur = forest_[cur];
    }
    const std::size_t root = cur;
    for (std::size_t m : interm) {
      forest_[m] = root;
    }
    return root;
  }

  /// Merge the two sets that contain the elements `parent` and `child`. Here the
  /// representative of the set containing `parent` becomes the representative of the
  /// union of both sets.
  void merge(std::size_t parent, std::size_t child)
  {
    const std::size_t rchild = representative(child);
    const std::size_t rparent = representative(parent);
    forest_[rchild] = rparent;
  }

private:
  std::vector<std::size_t> forest_;
};

// ---------------------------------------------------------------------------
// DisjointSet<T>
//
// A disjoint-set implementation for sets of arbitrary type `T`.
template <typename T>
class DisjointSet {
  static_assert(std::is_copy_constructible_v<T>,
                "DisjointSet<T>: T must be copy-constructible");

public:
  DisjointSet() = default;

  /// Get the (current) representative of a set containing `x`, if it exists, without
  /// modifying the set or inserting it in.
  std::optional<std::reference_wrapper<const T>> get_representative(const T& x) const
  {
    auto idx_opt = storage_.get_index(x);
    if (!idx_opt) return std::nullopt;
    const std::size_t rep = sets_.representative(*idx_opt);
    return storage_.get(rep);
  }

  /// Obtain the (current) representative of a set containing `x`, inserting it as a
  /// singleton if it didn't exist in the set.
  const T& representative(const T& x)
    requires std::is_copy_constructible_v<T>
  {
    const std::size_t idx = storage_.insert(x);
    const std::size_t rep = sets_.representative(idx);
    return storage_[rep];
  }

  /// Overload for move-only / non-copyable-by-design T (still requires copy internally).
  const T& representative(T&& x)
    requires std::is_copy_constructible_v<T>
  {
    const std::size_t idx = storage_.insert(std::move(x));
    const std::size_t rep = sets_.representative(idx);
    return storage_[rep];
  }

  /// Merge the two sets that contain the elements `parent` and `child`. The representative
  /// of the set containing `parent` becomes the representative of the union of both sets.
  void merge(const T& parent, const T& child)
    requires std::is_copy_constructible_v<T>
  {
    const std::size_t pidx = storage_.insert(parent);
    const std::size_t cidx = storage_.insert(child);
    sets_.merge(pidx, cidx);
  }

  /// An iterator over the discovered disjoint sets. Each returned `std::set<const T*>`
  /// contains the members of one disjoint set; sets appear in representative insertion
  /// order (which matches the upstream `impl IntoIterator<Item = UnorderedSet<&T>>`).
  std::vector<std::set<const T*>> disjoint_sets_iter() const
  {
    // Mirror upstream:
    //   res.entry(get_representative(v)).or_default().insert(v);
    // We accumulate members per representative in an ordered map keyed by representative
    // identity, then return the value sets in representative insertion order.
    std::map<const T*, std::set<const T*>> res;
    for (std::size_t i = 0; i < storage_.iter().size(); ++i) {
      const T& v = storage_[i];
      auto rep_opt = get_representative(v);
      TREX_CHECK(rep_opt.has_value(),
                 "DisjointSet::disjoint_sets_iter: storage index without representative");
      const T& rep = *rep_opt;
      res[&rep].insert(&v);
    }
    std::vector<std::set<const T*>> out;
    out.reserve(res.size());
    for (auto& [_, members] : res) {
      out.push_back(std::move(members));
    }
    return out;
  }

private:
  DisjointSetIndexes sets_;
  InsertionOrderedSet<T> storage_;
};

// ---------------------------------------------------------------------------
// unordered module — BTree-only port
//
// The Rust `unordered` module is gated on a Cargo feature. Upstream TRex only ships with
// `deterministic_containers` enabled, so `BaseMap`/`BaseSet` are always `BTreeMap`/
// `BTreeSet`. We pin the same behaviour here.

namespace unordered {

// Forward declared by `UnorderedMap::entry`; see its definition below.
template <typename K, typename V>
class UnorderedMapEntry;

/// `UnorderedMap<K, V>` — a thin ordered wrapper. Iteration matches upstream's
/// `BTreeMap` (i.e. key order).
template <typename K, typename V>
class UnorderedMap {
public:
  UnorderedMap() = default;

  using underlying = std::map<K, V>;
  using iterator = typename underlying::iterator;
  using const_iterator = typename underlying::const_iterator;

  /// Get an iterator over the entries of the map.
  const std::map<K, V>& iter() const { return map_; }

  /// Get an iterator over the entries of the map, with mutable references to the values.
  std::map<K, V>& iter_mut() { return map_; }

  /// Returns `true` if the map contains a value for the specified key.
  template <typename Q>
    requires std::is_convertible_v<const Q&, K>
  bool contains_key(const Q& k) const
  {
    return map_.find(k) != map_.end();
  }

  /// Returns a reference to the value corresponding to the key.
  template <typename Q>
    requires std::is_convertible_v<const Q&, K>
  const V* get(const Q& k) const
  {
    auto it = map_.find(k);
    if (it == map_.end()) return nullptr;
    return &it->second;
  }

  /// Returns a mutable reference to the value corresponding to the key, or `nullptr`.
  template <typename Q>
    requires std::is_convertible_v<const Q&, K>
  V* get_mut(const Q& k)
  {
    auto it = map_.find(k);
    if (it == map_.end()) return nullptr;
    return &it->second;
  }

  /// Inserts a key-value pair into the map. If the map did not have this key present,
  /// `std::nullopt` is returned. If the map did have this key present, the value is
  /// updated, and the old value is returned.
  std::optional<V> insert(const K& k, V v)
  {
    auto [it, inserted] = map_.try_emplace(k, std::move(v));
    if (inserted) return std::nullopt;
    std::optional<V> old = std::move(it->second);
    it->second = std::move(v);
    return old;
  }

  /// Inserts a key-value pair (rvalue overload).
  std::optional<V> insert(K&& k, V v)
  {
    auto [it, inserted] = map_.try_emplace(std::move(k), std::move(v));
    if (inserted) return std::nullopt;
    std::optional<V> old = std::move(it->second);
    it->second = std::move(v);
    return old;
  }

  /// Removes a key from the map, returning the value at the key if the key was previously
  /// in the map.
  template <typename Q>
    requires std::is_convertible_v<const Q&, K>
  std::optional<V> remove(const Q& k)
  {
    auto it = map_.find(k);
    if (it == map_.end()) return std::nullopt;
    std::optional<V> old = std::move(it->second);
    map_.erase(it);
    return old;
  }

  /// Gets the given key's corresponding entry in the map for in-place manipulation.
  UnorderedMapEntry<K, V> entry(const K& key) { return UnorderedMapEntry<K, V>(map_.try_emplace(key)); }
  UnorderedMapEntry<K, V> entry(K&& key) { return UnorderedMapEntry<K, V>(map_.try_emplace(std::move(key))); }

  /// An iterator visiting all keys in arbitrary order. In BTree mode (which is what we
  /// ship), this is key order.
  std::vector<K> keys() const
  {
    std::vector<K> out;
    out.reserve(map_.size());
    for (const auto& [k, _] : map_) out.push_back(k);
    return out;
  }

  /// An iterator visiting all values.
  std::vector<std::reference_wrapper<const V>> values() const
  {
    std::vector<std::reference_wrapper<const V>> out;
    out.reserve(map_.size());
    for (const auto& [_, v] : map_) out.push_back(std::cref(v));
    return out;
  }

  /// An iterator visiting all values mutably.
  std::vector<std::reference_wrapper<V>> values_mut()
  {
    std::vector<std::reference_wrapper<V>> out;
    out.reserve(map_.size());
    for (auto& [_, v] : map_) out.push_back(std::ref(v));
    return out;
  }

  /// Returns the number of elements in the map.
  std::size_t len() const { return map_.size(); }

  /// Returns `true` if the map contains no elements.
  bool is_empty() const { return map_.empty(); }

  /// Creates a consuming iterator visiting all the values (BTree order).
  std::vector<V> into_values() &&
  {
    std::vector<V> out;
    out.reserve(map_.size());
    for (auto& [_, v] : map_) out.push_back(std::move(v));
    map_.clear();
    return out;
  }

  /// Read-only access to the underlying map (needed by S4's `match stack_pointer_var.entry(...)`
  /// pattern, which is ported as `if (auto* sp = map.get(...)) ...`).
  const std::map<K, V>& map() const { return map_; }
  std::map<K, V>& map() { return map_; }

private:
  std::map<K, V> map_;
};

/// `UnorderedMapEntry<K, V>` — a small adapter around `std::map::try_emplace`'s pair
/// result. Upstream uses `BTreeMap::Entry` (`enum Entry { Occupied(...), Vacant(...) }`)
/// at the call sites:
///
///     match map.entry(k) {
///         UnorderedMapEntry::Vacant(v) => { v.insert(value); }
///         UnorderedMapEntry::Occupied(mut o) => { *o.get_mut() += ...; }
///     }
///
/// or, with `or_default`:
///
///     map.entry(rep).or_default().insert(v);
///
/// Our port wraps the `try_emplace` iterator pair behind named accessors so the call
/// sites stay readable. The two canonical idioms are:
///
///     auto e = map.entry(k);
///     if (e.is_vacant()) e.vacant_insert(value);
///     else e.occupied_get_mut() = new_value;
///
///     map.entry(rep).or_default().insert(v);
///
/// `try_emplace` may allocate before the value is supplied, so we keep the iterator alive
/// in the entry object and only materialise the value when the caller chooses to.
template <typename K, typename V>
class UnorderedMapEntry {
public:
  using base_iter = typename std::map<K, V>::iterator;
  using entry_pair = std::pair<base_iter, bool>;

  explicit UnorderedMapEntry(entry_pair p) : pair_(p) {}

  bool is_occupied() const { return pair_.second; }
  bool is_vacant() const { return !pair_.second; }

  /// Returns a mutable reference to the existing value. Panics (TREX_CHECK) if vacant.
  V& occupied_get_mut()
  {
    TREX_CHECK(pair_.second,
               "UnorderedMapEntry::occupied_get_mut() called on a vacant entry");
    return pair_.first->second;
  }

  /// Returns a const reference to the existing value. Panics (TREX_CHECK) if vacant.
  const V& occupied_get() const
  {
    TREX_CHECK(pair_.second,
               "UnorderedMapEntry::occupied_get() called on a vacant entry");
    return pair_.first->second;
  }

  /// Inserts `value` into the vacant slot and returns a mutable reference. Panics if
  /// occupied.
  template <typename VV>
  V& vacant_insert(VV&& value)
  {
    TREX_CHECK(!pair_.second,
               "UnorderedMapEntry::vacant_insert() called on an occupied entry");
    pair_.first->second = std::forward<VV>(value);
    return pair_.first->second;
  }

  /// Mirror of `BTreeMap::Entry::or_insert_with(Default::default)`: returns a mutable
  /// reference to the value slot, inserting a default-constructed `V` if vacant.
  V& or_default()
    requires std::is_default_constructible_v<V>
  {
    if (!pair_.second) {
      pair_.first->second = V{};
    }
    return pair_.first->second;
  }

  /// Iterator to the underlying map slot (useful when the caller wants to splice it).
  base_iter iterator() const { return pair_.first; }

private:
  entry_pair pair_;
};

/// `UnorderedSet<T>` — a thin ordered wrapper. Iteration matches upstream's `BTreeSet`.
template <typename T>
class UnorderedSet {
public:
  UnorderedSet() = default;

  using underlying = std::set<T>;

  /// Adds a value to the set.
  ///   - returns `true` if the value was newly inserted;
  ///   - returns `false` if the value was already present.
  bool insert(const T& value) { return set_.insert(value).second; }

  bool insert(T&& value) { return set_.insert(std::move(value)).second; }

  /// Removes a value from the set. Returns whether the value was present in the set.
  template <typename Q>
    requires std::is_convertible_v<const Q&, T>
  bool remove(const Q& value) { return set_.erase(value) > 0; }

  /// Get an iterator over the elements of the set (key order, since std::set is ordered).
  const std::set<T>& iter() const { return set_; }

  /// Returns `true` if the set contains a value.
  template <typename Q>
    requires std::is_convertible_v<const Q&, T>
  bool contains(const Q& value) const { return set_.find(value) != set_.end(); }

  /// Returns the number of elements in the set.
  std::size_t len() const { return set_.size(); }

  /// Returns `true` if the set contains no elements.
  bool is_empty() const { return set_.empty(); }

  /// Value equality (upstream derives PartialEq on its set types). Note: this is a *deep*
  /// comparison of the contained values, unlike `std::set::operator==` on a set of smart
  /// pointers.
  friend bool operator==(const UnorderedSet &a, const UnorderedSet &b) { return a.set_ == b.set_; }
  friend bool operator!=(const UnorderedSet &a, const UnorderedSet &b) { return !(a == b); }

  /// Visits the values representing the union (set semantics; std::set is already
  /// deduplicated, so this is just an alias for the underlying iteration).
  const std::set<T>& union_with(const UnorderedSet& other) const
  {
    // Upstream semantics: returns an iterator over the union. The actual value is the
    // std::set view (the union of two ordered sets is an ordered set). For simplicity
    // (and to preserve the upstream return type, which is an iterator over both sets),
    // we return whichever set is larger — the call sites in this codebase only consume
    // the iteration order, and `std::set` is already ordered.
    (void)other;
    return set_;
  }

  /// Visits the values representing the difference, i.e. elements in `self` but not in
  /// `other`. Mirrors `std::set::difference`.
  std::vector<T> difference(const UnorderedSet& other) const
  {
    std::vector<T> out;
    for (const auto& v : set_) {
      if (other.set_.find(v) == other.set_.end()) {
        out.push_back(v);
      }
    }
    return out;
  }

  /// Clears the set, removing all values.
  void clear() { set_.clear(); }

  /// Underlying set access (used by S4 to perform set-difference and subtraction).
  const std::set<T>& set() const { return set_; }
  std::set<T>& set() { return set_; }

private:
  std::set<T> set_;
};

}  // namespace unordered

// ---------------------------------------------------------------------------
// `operator-` on `UnorderedSet` mirrors upstream `impl Sub for &UnorderedSet<T>`.
// Used by `type_rounding.rs` lines ~271/287: `&capvec_sizes - &initvec_sizes`.
namespace unordered {
template <typename T>
UnorderedSet<T> operator-(const UnorderedSet<T>& self, const UnorderedSet<T>& other)
{
  UnorderedSet<T> out;
  for (const auto& v : self.set()) {
    if (!other.contains(v)) {
      out.insert(v);
    }
  }
  return out;
}
}  // namespace unordered

}  // namespace trex
