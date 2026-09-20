// A convenient container abstraction to help manage recursive
// objects that support some sort of "join" operation on them.
//
// 1:1 port of `third_party/trex/trex/src/joinable_container.rs` (641 lines) into C++20.
//
// The Rust uses `Rc<RefCell<T>>` for shared interior-mutable state; in this single-threaded
// port that's a `std::shared_ptr<T>` with a `mutable` qualifier on the fields of
// `Container` that need to be mutated through `&self` (matching the upstream `RefCell`
// contract). `Rc::clone(x)` is `x` (shared_ptr copy is the default ctor).
//
// Layout note: `Container<T>` and `IndexMap<V>` are class templates, so their bodies live
// inline in this header. `DelayedJoiner` is non-templated and is defined in
// `joinable_container.cpp`.
//
// Trait contract: upstream `trait Joinable` becomes a C++20 concept, `JoinableType`. The
// concrete `StructuralType` (defined by S4) satisfies it via duck typing — no virtual
// base class, because `Container<T>` stores `T` by value and the `Result<(), Self>` shape
// is a by-value return.

#pragma once

#include <atomic>
#include <compare>
#include <concepts>
#include <cstddef>
#include <deque>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <trex/error.hpp>

namespace trex {

// ---------------------------------------------------------------------------
// Index
//
// An opaque index into the `Container`. Upstream deliberately does *not* implement
// PartialEq/Eq/Hash; instead `Container::index_eq` is the equality check, and
// `Index::some_consistent_ordering` is the ordering. Our port adds `operator<=>` and
// `operator==` so `Index` can be used as an ordered map key (the port's `IndexSet` and
// `IndexMap` need that), but the semantics match upstream exactly: compare
// `(container_id, idx)` lexicographically.
struct Index {
  std::size_t container_id = 0;
  std::size_t idx = 0;

  /// Convert to a string. Used only for debugging / `.dot` generation, per upstream.
  std::string to_string() const { return std::to_string(idx); }

  /// Equality comparison that returns true if the two indices are guaranteed to point to
  /// the same value. If it returns false, then nothing can be said about the indices
  /// (i.e. they may or may not point to the same value). See `Container::index_eq` for
  /// the value-level comparison.
  bool surely_equal(const Index& other) const
  {
    return container_id == other.container_id && idx == other.idx;
  }

  /// Comparison consistent with `surely_equal`; a partial ordering on all indexes, but
  /// otherwise provides no special guarantees.
  std::strong_ordering some_consistent_ordering(const Index& other) const
  {
    if (auto c = container_id <=> other.container_id; c != 0) return c;
    return idx <=> other.idx;
  }

  friend bool operator==(const Index&, const Index&) = default;
  friend std::strong_ordering operator<=>(const Index&, const Index&) = default;
};

// Forward declaration so `JoinableType`'s requires-clause can mention `DelayedJoiner`.
class DelayedJoiner;
// ---------------------------------------------------------------------------
// JoinableType (concept)
//
// C++20 concept equivalent of upstream `trait Joinable: Sized`. The contract:
//
//   - `join(&mut self, other: Self, delayed_joiner: &mut DelayedJoiner) -> Result<(), Self>`
//     In C++: `std::optional<T>` returned by value. `std::nullopt` corresponds to
//     `Ok(())` (the join succeeded; `other` was consumed into `*self`). A present
//     optional carries the rejected `other` back to the caller, who then puts it back
//     in its slot — matching the Rust `Err(from_obj)` arm.
//
//   - `refers_to<'a>(&'a self) -> Box<dyn Iterator<Item = Index> + 'a>`
//     In C++: `std::vector<Index>` (owned copies).
//
//   - `refers_to_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut Index> + 'a>`
//     In C++: `std::vector<Index*>` (raw pointers valid for the borrow of `self`).
//     The pointers must be used before any further mutation of `self` (the call sites in
//     upstream are local — no escape).
//
// `Clone` (Rust) maps to `std::copy_constructible<T>` here. `Container<T>` uses
// copy-construction for `clone_at`, `deep_clone`, and the join loop's `clone_and_join`
// step (which corresponds to Rust's `self.objects[i1].clone()`).
template <class T>
concept JoinableType = std::copy_constructible<T>
  && requires(T& self, T other, DelayedJoiner& dj) {
    { self.join(std::move(other), dj) } -> std::same_as<std::optional<T>>;
    { self.refers_to() } -> std::same_as<std::vector<Index>>;
    { self.refers_to_mut() } -> std::same_as<std::vector<Index*>>;
  };

// ---------------------------------------------------------------------------
// Forward declaration: DelayedJoiner::new_for<T> / clear_any_pre_joined_indexes<T>
// (member templates of DelayedJoiner, defined inline below) take `const Container<T>&`
// and call its members. Full `Container<T>` definition follows.
// NOTE: the parameter is deliberately *unconstrained* here. Constraining it would make forming a
// template-id such as `Container<StructuralType>` require a complete StructuralType, which is
// impossible for member declarations that appear inside StructuralType itself (e.g. its
// `aggregate_size(Container<StructuralType>&, ...)` parameter). The concept is enforced by a
// static_assert inside the class body instead.
template <class T> class Container;

// ---------------------------------------------------------------------------
// DelayedJoiner
//
// Structure that allows scheduling joins to happen after the ongoing `Joinable::join`
// that discovered them is completed. The two-queue (index_pairs + clone_and_join_indexes)
// drain order is load-bearing: `structural.rs` relies on the specific join sequence.
class DelayedJoiner {
public:
  DelayedJoiner() = default;

  /// A new, empty delayed joiner; should not need to be created manually except in special
  /// circumstances. The container passed in allows for control over clone-and-join style
  /// operations.
  template <typename T>
  static DelayedJoiner new_for(const Container<T>& container);

  /// Schedule a delayed join.
  void schedule(const Index& into_index, const Index& from_index);

  /// Schedule a delayed clone-and-join. Returns a new index for the future newly created
  /// member that is the join of `index1` and `index2`.
  Index schedule_clone_and_join(const Index& index1, const Index& index2);

  /// Return `true` if no delayed joins (or clone-and-joins) were scheduled.
  bool is_empty() const;

  /// Clear all pairs of pre-joined indexes by looking through the container.
  template <typename T>
  void clear_any_pre_joined_indexes(const Container<T>& container);

  // ----- Accessors used by Container (module-private in Rust; public here for the .cpp) -----

  /// Pop the most-recently pushed `(into, from)` pair. Returns `std::nullopt` when empty.
  /// (Upstream uses `Vec::pop` which is LIFO; we preserve the LIFO order.)
  std::optional<std::pair<Index, Index>> pop_index_pair();

  /// Pop the front of the clone-and-join deque (FIFO, mirroring `VecDeque::pop_front`).
  std::optional<std::tuple<Index, Index, Index>> pop_clone_and_join();

  /// Read-only view of the LIFO index-pair queue (used by `Container::deep_clone`).
  const std::vector<std::pair<Index, Index>>& index_pairs_view() const { return index_pairs_; }

  /// Read-only view of the FIFO clone-and-join deque.
  const std::deque<std::tuple<Index, std::pair<Index, Index>>>& clone_and_join_view() const
  {
    return clone_and_join_indexes_;
  }

  std::shared_ptr<std::size_t> reserved_freshness() const { return reserved_freshness_; }
  std::size_t container_id() const { return container_id_; }

private:
  /// Mirrors `DelayedJoiner::internal_new`.
  static DelayedJoiner internal_new(std::shared_ptr<std::size_t> reserved_freshness,
                                    std::size_t container_id);

  /// Mirrors `DelayedJoiner::reserve_index`. Bumps the shared freshness counter.
  Index reserve_index();

  std::vector<std::pair<Index, Index>> index_pairs_;
  std::deque<std::tuple<Index, std::pair<Index, Index>>> clone_and_join_indexes_;
  std::shared_ptr<std::size_t> reserved_freshness_;
  std::size_t container_id_ = 0;
};

// ---------------------------------------------------------------------------
// Container<T: JoinableType>
//
// A container that holds recursive `Joinable` objects. Recursion is managed through
// opaque `Index`es.
template <class T>
class Container {
  static_assert(JoinableType<T>,
                "Container<T> requires T: join(T, DelayedJoiner&) -> std::optional<T>, "
                "refers_to() -> std::vector<Index>, refers_to_mut() -> std::vector<Index*>");
public:
  /// Create a new, empty container.
  Container()
      : reserved_freshness_(std::make_shared<std::size_t>(0)),
        container_id_(next_container_id()),
        index_map_(),
        objects_(),
        delayed_joiner_(DelayedJoiner::new_for(*this))
  {}

  ~Container() = default;

  Container(const Container&) = delete;
  Container& operator=(const Container&) = delete;
  Container(Container&&) = default;
  Container& operator=(Container&&) = default;

  /// Insert `value` into the container, returning an index for referring to it.
  Index insert(T value)
  {
    TREX_CHECK(objects_.size() == index_map_.size(),
               "Container::insert: index_map/objects length invariant broken before insert");
    const std::size_t reserved = *reserved_freshness_;
    TREX_CHECK(index_map_.size() <= reserved,
               "Container::insert: index_map.len() > reserved_freshness");
    // Fill any reserved-but-not-yet-allocated slots.
    while (index_map_.size() < reserved) {
      index_map_.push_back(index_map_.size());
      objects_.push_back(std::nullopt);
    }
    TREX_CHECK(objects_.size() == index_map_.size(),
               "Container::insert: index_map/objects length invariant broken after fill");

    const std::size_t o = objects_.size();
    objects_.push_back(std::move(value));
    const std::size_t fresh_idx = index_map_.size();
    index_map_.push_back(o);
    *reserved_freshness_ = reserved + 1;
    TREX_CHECK(index_map_.size() <= *reserved_freshness_,
               "Container::insert: index_map.len() > reserved_freshness after insert");
    return Index{container_id_, fresh_idx};
  }

  /// Get the "canonical" index for a given index.
  Index get_canonical_index(const Index& index) const
  {
    return Index{container_id_, get_obj_index(index)};
  }

  /// Attempt to join the value at `from_index` into the value at `into_index`. Both
  /// indices continue to remain valid for this container, and now refer to the newly
  /// joined object. Any extra delayed joins (or clone-and-joins) scheduled into the
  /// `DelayedJoiner` are also performed before this function returns.
  void join(const Index& into_index, const Index& from_index)
  {
    // Local cache of indices already cloned during this joining cycle, mirroring the
    // `already_cloned_objects` map in upstream (BTreeMap<usize, usize>).
    std::map<std::size_t, std::size_t> already_cloned_objects;

    join_one(into_index, from_index);
    while (!delayed_joiner_.is_empty()) {
      while (auto p = delayed_joiner_.pop_index_pair()) {
        join_one(p->first, p->second);
      }
      // Squeeze out any reserved freshness into the index_map/objects vectors.
      {
        const std::size_t reserved = *reserved_freshness_;
        TREX_CHECK(index_map_.size() <= reserved,
                   "Container::join: index_map.len() > reserved_freshness in squeeze");
        while (index_map_.size() < reserved) {
          index_map_.push_back(index_map_.size());
          objects_.push_back(std::nullopt);
        }
      }
      while (auto t = delayed_joiner_.pop_clone_and_join()) {
        const auto& [cloned_idx, idx1, idx2] = *t;
        const std::size_t cloned_i = get_obj_index(cloned_idx);
        const std::size_t i1 = get_obj_index(idx1);
        const std::size_t i2 = get_obj_index(idx2);
        TREX_CHECK(cloned_idx.idx == cloned_i,
                   "Container::join: cloned_idx must already be canonical");
        TREX_CHECK(!objects_[cloned_i].has_value(),
                   "Container::join: cloned slot must be empty before clone-and-join");
        TREX_CHECK(objects_[i1].has_value(),
                   "Container::join: idx1 slot must hold a live object");
        TREX_CHECK(objects_[i2].has_value(),
                   "Container::join: idx2 slot must hold a live object");

        if (auto it = already_cloned_objects.find(i1); it != already_cloned_objects.end()) {
          // Already cloned during this joining cycle: re-point and schedule a non-clone
          // join so recursive objects are handled correctly.
          index_map_[cloned_i] = it->second;
          delayed_joiner_.schedule(cloned_idx, idx2);
        } else {
          objects_[cloned_i] = objects_[i1];  // copy-construct (Rust: self.objects[i1].clone())
          delayed_joiner_.schedule(cloned_idx, idx2);
          already_cloned_objects.emplace(i1, cloned_i);
        }
      }
    }
  }

  /// Make a clone of the value at `index` and return an index to the clone.
  Index clone_at(const Index& index)
  {
    T copy = get(index);  // copy-construct (Rust: self.get(index).clone())
    return insert(std::move(copy));
  }

  /// Convenience: `self.types[idx]` from upstream becomes `container[idx]`. Mirrors Rust's
  /// `Index` impl. Returns `get(idx)`.
  T &operator[](const Index &index) { return get(index); }
  const T &operator[](const Index &index) const { return get(index); }
  /// Get a reference to the value referred to by `index`.
  T &get(const Index &index)
  {
    const std::size_t idx = get_obj_index(index);
    TREX_CHECK(objects_[idx].has_value(),
               "Container::get: index points to a slot with no live object");
    return *objects_[idx];
  }
  const T &get(const Index &index) const
  {
    const std::size_t idx = get_obj_index(index);
    TREX_CHECK(objects_[idx].has_value(),
               "Container::get (const): index points to a slot with no live object");
    return *objects_[idx];
  }

  /// Get a mutable reference to the value referred to by `index`.
  T& get_mut(const Index& index)
  {
    const std::size_t idx = get_obj_index(index);
    TREX_CHECK(objects_[idx].has_value(),
               "Container::get_mut: index points to a slot with no live object");
    return *objects_[idx];
  }

  /// Check if two indices point to the same value.
  bool index_eq(const Index& a, const Index& b) const
  {
    return get_obj_index(a) == get_obj_index(b);
  }

  /// Perform garbage collection on the container, keeping objects alive that are
  /// reachable from the given `accessible_roots`.
  void garbage_collect_with_roots(std::vector<Index> accessible_roots)
  {
    std::set<std::size_t> keep_alive;

    std::vector<std::size_t> worklist;
    worklist.reserve(accessible_roots.size());
    for (const Index& i : accessible_roots) {
      worklist.push_back(get_obj_index(i));
    }

    while (!worklist.empty()) {
      const std::size_t idx = worklist.back();
      worklist.pop_back();
      keep_alive.insert(idx);
      for (const Index& j : objects_[idx].value().refers_to()) {
        const std::size_t j_obj = get_obj_index(j);
        if (!keep_alive.contains(j_obj)) {
          worklist.push_back(j_obj);
        }
      }
    }

    for (std::size_t i = 0; i < objects_.size(); ++i) {
      if (objects_[i].has_value() && !keep_alive.contains(i)) {
        objects_[i] = std::nullopt;
      }
    }
  }

  /// Get an iterator to all currently alive objects.
  std::vector<std::reference_wrapper<const T>> currently_alive_objects_iter() const
  {
    std::vector<std::reference_wrapper<const T>> out;
    for (const auto& o : objects_) {
      if (o.has_value()) out.push_back(std::cref(*o));
    }
    return out;
  }

  /// Get a mutable iterator to all currently alive objects.
  std::vector<std::reference_wrapper<T>> currently_alive_objects_iter_mut()
  {
    std::vector<std::reference_wrapper<T>> out;
    for (auto& o : objects_) {
      if (o.has_value()) out.push_back(std::ref(*o));
    }
    return out;
  }

  /// Get an iterator to canonical indices to all currently alive objects.
  std::vector<Index> currently_alive_canon_indices_iter() const
  {
    std::vector<Index> out;
    for (std::size_t i = 0; i < objects_.size(); ++i) {
      if (objects_[i].has_value()) {
        out.push_back(Index{container_id_, i});
      }
    }
    return out;
  }

  /// Make a deep clone of the container, updating any indexes (including internal
  /// indices) as necessary to produce a completely disjoint container.
  Container<T> deep_clone(std::vector<Index*> roots) const
  {
    TREX_CHECK(*reserved_freshness_ == index_map_.size(),
               "Container::deep_clone: should not have any unused freshness yet to be squeezed out");
    TREX_CHECK(delayed_joiner_.index_pairs_view().empty(),
               "Container::deep_clone: unsupported — deep cloning a container that is in the middle of joining");

    Container<T> r;
    for (Index* x : roots) {
      x->container_id = r.container_id_;
    }
    r.index_map_ = index_map_;
    r.objects_ = objects_;
    r.delayed_joiner_ = DelayedJoiner::new_for(r);
    for (auto& o : r.objects_) {
      if (o.has_value()) {
        for (Index* idx : o->refers_to_mut()) {
          idx->container_id = r.container_id_;
        }
      }
    }
    *r.reserved_freshness_ = r.index_map_.size();
    return r;
  }

  /// Insert the default element of `T` into the container.
  Index insert_default() { return insert(T{}); }

  // ----- Accessors used by DelayedJoiner -----
  std::size_t container_id() const { return container_id_; }
  std::shared_ptr<std::size_t> reserved_freshness() const { return reserved_freshness_; }

  /// Mirrors `get_obj_index` from upstream. Mutates `index_map_` (path compression) so
  /// the field is `mutable`.
  std::size_t get_obj_index(const Index& index) const
  {
    TREX_CHECK(index.container_id == container_id_,
               "Container::get_obj_index: using index for container id "
               "%zu in container id %zu",
               index.container_id, container_id_);

    // Find the root via union-find chaining.
    std::size_t root = index.idx;
    while (root != index_map_[root]) {
      TREX_CHECK(!objects_[root].has_value(),
                 "Container::get_obj_index: non-root index points to a live object");
      root = index_map_[root];
    }
    // Path compression.
    std::size_t cur = index.idx;
    while (cur != index_map_[cur]) {
      const std::size_t next = index_map_[cur];
      index_map_[cur] = root;
      cur = next;
    }
    return root;
  }

  /// Attempts to join a single value from `from_index` into the value at `into_index`.
  void join_one(const Index& into_index, const Index& from_index)
  {
    const std::size_t into_idx = get_obj_index(into_index);
    const std::size_t from_idx = get_obj_index(from_index);
    if (into_idx == from_idx) {
      return;
    }
    T from_obj = std::move(*objects_[from_idx]);
    objects_[from_idx] = std::nullopt;
    // Move `from_obj` into `*objects_[into_idx].join(...)`; `nullopt` ↔ Ok (other
    // consumed), `std::optional<T>(other)` ↔ Err (return other to caller).
    if (auto rejected = objects_[into_idx]->join(std::move(from_obj), delayed_joiner_)) {
      // Join rejected: put the value back where it came from.
      objects_[from_idx].emplace(std::move(*rejected));
    } else {
      index_map_[from_idx] = into_idx;
    }
  }

  /// Total containers created since program start (matches upstream `CONTAINER_COUNT`).
  static std::size_t next_container_id()
  {
    static std::atomic<std::size_t> counter{0};
    return counter.fetch_add(1, std::memory_order_seq_cst);
  }

private:
  std::shared_ptr<std::size_t> reserved_freshness_;
  std::size_t container_id_;
  // `index_map` is mutated through `&self` (mirrors Rust's `RefCell<Vec<usize>>`).
  mutable std::vector<std::size_t> index_map_;
  std::vector<std::optional<T>> objects_;
  DelayedJoiner delayed_joiner_;
};

// ---------------------------------------------------------------------------
// DelayedJoiner template-member definitions (out-of-line so the body can see the
// complete `Container<T>` definition above).

template <typename T>
DelayedJoiner DelayedJoiner::new_for(const Container<T>& container)
{
  return internal_new(container.reserved_freshness(), container.container_id());
}

template <typename T>
void DelayedJoiner::clear_any_pre_joined_indexes(const Container<T>& container)
{
  TREX_CHECK(container_id_ == container.container_id(),
             "DelayedJoiner::clear_any_pre_joined_indexes: container id mismatch");
  std::vector<std::pair<Index, Index>> kept;
  kept.reserve(index_pairs_.size());
  for (const auto& p : index_pairs_) {
    if (!container.index_eq(p.first, p.second)) {
      kept.push_back(p);
    }
  }
  index_pairs_ = std::move(kept);
}

// ---------------------------------------------------------------------------
// IndexSet — a set of `Index`es.
class IndexSet {
public:
  IndexSet() = default;

  /// Returns `true` if the set contains `idx`.
  bool contains(const Index& idx) const
  {
    return set_.contains(idx);
  }

  /// Adds `idx` to the set. Returns `true` if it was newly inserted, `false` otherwise.
  bool insert(const Index& idx) { return set_.insert(idx).second; }

  /// Iterate over the elements of the set (in Index order).
  const std::set<Index>& iter() const { return set_; }

  std::size_t len() const { return set_.size(); }
  bool is_empty() const { return set_.empty(); }
  void clear() { set_.clear(); }

private:
  std::set<Index> set_;
};

// ---------------------------------------------------------------------------
// IndexMap<V> — a map of `Index`es to `V`.
template <typename V>
class IndexMap {
public:
  IndexMap() = default;

  /// An iterator over the map (key order, since `std::map` is ordered).
  std::vector<std::pair<Index, std::reference_wrapper<const V>>> iter() const
  {
    std::vector<std::pair<Index, std::reference_wrapper<const V>>> out;
    out.reserve(map_.size());
    for (const auto& [k, v] : map_) {
      out.emplace_back(k, std::cref(v));
    }
    return out;
  }

  /// Convert the map into an iterator (consumes the map).
  std::vector<std::pair<Index, V>> into_iter() &&
  {
    std::vector<std::pair<Index, V>> out;
    out.reserve(map_.size());
    for (auto& [k, v] : map_) {
      out.emplace_back(k, std::move(v));
    }
    map_.clear();
    return out;
  }

  /// Returns a reference to the value corresponding to `k`, or `nullptr` if absent.
  const V* get(const Index& k) const
  {
    auto it = map_.find(k);
    if (it == map_.end()) return nullptr;
    return &it->second;
  }

  /// Returns a mutable reference to the value corresponding to `k`, or `nullptr` if
  /// absent.
  V* get_mut(const Index& k)
  {
    auto it = map_.find(k);
    if (it == map_.end()) return nullptr;
    return &it->second;
  }

  /// Returns `true` if the map contains no elements.
  bool is_empty() const { return map_.empty(); }
  std::size_t len() const { return map_.size(); }

  /// Inserts a key-value pair into the map. Returns `std::nullopt` if the key was newly
  /// inserted; returns the old value if the key was present.
  std::optional<V> insert(const Index& k, V v)
  {
    auto [it, inserted] = map_.try_emplace(k, std::move(v));
    if (inserted) return std::nullopt;
    std::optional<V> old = std::move(it->second);
    it->second = std::move(v);
    return old;
  }

  /// `from_iter` analogue — used by upstream's `FromIterator<(Index, V)>` impl.
  static IndexMap<V> from_iter(std::vector<std::pair<Index, V>> items)
  {
    IndexMap<V> out;
    for (auto& [k, v] : items) {
      out.map_.emplace(k, std::move(v));
    }
    return out;
  }

  /// Direct access to the underlying `std::map` (useful for tests / range iteration).
  const std::map<Index, V>& map() const { return map_; }

private:
  std::map<Index, V> map_;
};

}  // namespace trex
