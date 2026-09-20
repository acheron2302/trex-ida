// `DelayedJoiner` is the only non-template component of `joinable_container`. The
// rest of the port is class templates whose bodies must live in `joinable_container.hpp`
// (so any translation unit that instantiates `Container<T>` sees them). The definitions
// here mirror the corresponding `impl DelayedJoiner` block in
// `third_party/trex/trex/src/joinable_container.rs`.

#include <trex/joinable_container.hpp>

#include <utility>

namespace trex {

// ---------------------------------------------------------------------------
// DelayedJoiner — non-template definitions.
//
// The `trace!()` call in upstream's `schedule` (for the surely_equal branch) is
// deliberately elided: the upstream slog is routed to stderr/JSON by `log.rs`, and
// `structural.rs` never reads back the message. Replacing it with a no-op preserves
// observable behaviour.

void DelayedJoiner::schedule(const Index& into_index, const Index& from_index)
{
  TREX_CHECK(into_index.container_id == container_id_,
             "DelayedJoiner::schedule: into_index.container_id mismatch (got %zu, want %zu)",
             into_index.container_id, container_id_);
  TREX_CHECK(from_index.container_id == container_id_,
             "DelayedJoiner::schedule: from_index.container_id mismatch (got %zu, want %zu)",
             from_index.container_id, container_id_);
  if (into_index.surely_equal(from_index)) {
    return;
  }
  index_pairs_.emplace_back(into_index, from_index);
}

Index DelayedJoiner::schedule_clone_and_join(const Index& index1, const Index& index2)
{
  const Index new_idx = reserve_index();
  clone_and_join_indexes_.emplace_back(new_idx, std::pair{index1, index2});
  return new_idx;
}

bool DelayedJoiner::is_empty() const
{
  return index_pairs_.empty() && clone_and_join_indexes_.empty();
}

// ---------------------------------------------------------------------------
// Private members.

DelayedJoiner DelayedJoiner::internal_new(std::shared_ptr<std::size_t> reserved_freshness,
                                         std::size_t container_id)
{
  DelayedJoiner d;
  d.reserved_freshness_ = std::move(reserved_freshness);
  d.container_id_ = container_id;
  return d;
}

Index DelayedJoiner::reserve_index()
{
  TREX_CHECK(reserved_freshness_,
             "DelayedJoiner::reserve_index: null reserved_freshness");
  const std::size_t idx = *reserved_freshness_;
  *reserved_freshness_ += 1;
  return Index{container_id_, idx};
}

std::optional<std::pair<Index, Index>> DelayedJoiner::pop_index_pair()
{
  if (index_pairs_.empty()) return std::nullopt;
  auto p = std::move(index_pairs_.back());
  index_pairs_.pop_back();
  return p;
}

std::optional<std::tuple<Index, Index, Index>> DelayedJoiner::pop_clone_and_join()
{
  if (clone_and_join_indexes_.empty()) return std::nullopt;
  auto front = std::move(clone_and_join_indexes_.front());
  clone_and_join_indexes_.pop_front();
  // The deque element is (Index new_idx, (Index, Index)). Decompose into (new_idx, idx1, idx2).
  return std::tuple{std::get<0>(front), std::get<1>(front).first, std::get<1>(front).second};
}

}  // namespace trex
