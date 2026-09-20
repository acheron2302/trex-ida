// Implementation of `type_rounding` (port of upstream `trex/src/type_rounding.rs`).
//
// `CapabilityVec` is an internal representation of a structural type's
// capabilities, used to compare two types for the rounding relation
// ("is_smaller_type_than"). `round_up` runs a greedy algorithm: starting
// from the union of every allowed primitive, repeatedly subtract the
// "most expensive" primitive that the target type doesn't actually need.
//
// `round_up_to_c_types` is the public wrapper. It calls `round_up` with
// the standard C primitive set and then applies the two CONFIG-driven
// rewrites (undefined-N->integer, signed/unsigned collapse).
//
// `recognize_union_of_c_primitives` is the second public wrapper. It
// wraps the input in a temporary `Container`, runs `round_up`, and
// extracts the set of names used.

#include <trex/type_rounding.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <trex/c_types.hpp>
#include <trex/inference_config.hpp>
#include <trex/joinable_container.hpp>
#include <trex/log.hpp>
#include <sstream>

namespace trex {

// ---------------------------------------------------------------------------
// RoundedIdx::to_string
std::string RoundedIdx::to_string() const
{
  if (kind == Kind::Primitive) {
    return name;
  }
  return "padding[" + std::to_string(padding_bytes) + "]";
}

namespace {
struct CapabilityVec
{
  uint64_t cap_is_pointer = 0;
  uint64_t cap_is_code = 0;
  uint64_t cap_zero_comparable = 0;
  uint64_t cap_observed_boolean = 0;
  std::map<std::pair<size_t, size_t>, uint64_t> cap_upper_bound_sizes;
  std::map<size_t, uint64_t> cap_copy_sizes;
  std::map<std::pair<IntegerOp, size_t>, uint64_t> cap_integer_ops;
  std::map<std::pair<BooleanOp, size_t>, uint64_t> cap_boolean_ops;
  std::map<std::pair<FloatOp, size_t>, uint64_t> cap_float_ops;

  /// Returns `true` iff `self`'s capabilities are a (non-strict) subset of
  /// the capabilities of `other`.
  bool is_smaller_type_than(const CapabilityVec &other) const
  {
    return !reason_not_smaller_type_than(other).has_value();
  }

  /// Returns the reason `self`'s capabilities are not a (non-strict) subset
  /// of the capabilities of `other`. Mirrors upstream
  /// `reason_not_smaller_type_than`.
  std::optional<std::string> reason_not_smaller_type_than(const CapabilityVec &other) const
  {
    auto mapfail = [](const std::string &t, const auto &x,
                      const auto &y) -> std::optional<std::string> {
      using K = std::remove_const_t<decltype(x.begin()->first)>;
      std::vector<K> res;
      for (const auto &[k, count] : x) {
        auto yit = y.find(k);
        uint64_t yv = (yit == y.end()) ? 0 : yit->second;
        if (count > yv) {
          res.push_back(k);
        }
      }
      if (res.empty()) {
        return std::nullopt;
      }
      return std::string("missing capabilities in " + t);
    };
    // NOTE: `cap_is_pointer` is checked first, as upstream does. Without this check a non-pointer
    // primitive such as `ULong` looks like a superset of a pointer type and every pointer rounds
    // down to an integer.
    if (cap_is_pointer > other.cap_is_pointer)
      return std::string("cap_is_pointer");
    if (cap_is_code > other.cap_is_code)
      return std::string("cap_is_code");
    if (cap_zero_comparable > other.cap_zero_comparable)
      return std::string("cap_zero_comparable");
    if (cap_observed_boolean > other.cap_observed_boolean)
      return std::string("cap_observed_boolean");
    if (auto r = mapfail("cap_upper_bound_sizes", cap_upper_bound_sizes, other.cap_upper_bound_sizes))
      return r;
    if (auto r = mapfail("cap_copy_sizes", cap_copy_sizes, other.cap_copy_sizes))
      return r;
    if (auto r = mapfail("cap_integer_ops", cap_integer_ops, other.cap_integer_ops))
      return r;
    if (auto r = mapfail("cap_boolean_ops", cap_boolean_ops, other.cap_boolean_ops))
      return r;
    if (auto r = mapfail("cap_float_ops", cap_float_ops, other.cap_float_ops))
      return r;
    return std::nullopt;
  }

  /// Returns the ordering of `self` compared to `rhs`, in terms of
  /// expensiveness.
  std::strong_ordering compare_expensiveness_to(const CapabilityVec &rhs) const
  {
    auto mapcmp = [](const auto &x, const auto &y) -> std::strong_ordering {
      size_t xn = 0, yn = 0;
      for (const auto &[_, v] : x)
        if (v > 0) ++xn;
      for (const auto &[_, v] : y)
        if (v > 0) ++yn;
      return xn <=> yn;
    };

    auto combine = [](std::strong_ordering a, std::strong_ordering b) -> std::strong_ordering {
      return a == std::strong_ordering::equal ? b : a;
    };

    std::strong_ordering res = std::strong_ordering::equal;
    res = combine(res, cap_is_pointer <=> rhs.cap_is_pointer);
    res = combine(res, cap_is_code <=> rhs.cap_is_code);

    if (config().prefer_signed_integers_when_rounding) {
      auto unsigned_filter = [](const auto &m) {
        std::map<std::pair<IntegerOp, size_t>, uint64_t> r;
        for (const auto &[k, v] : m) {
          std::optional<bool> sign = is_signed_op(k.first);
          if (sign.has_value() && !*sign) {
            r[k] = v;
          }
        }
        return r;
      };
      auto x = unsigned_filter(cap_integer_ops);
      auto y = unsigned_filter(rhs.cap_integer_ops);
      res = combine(res, mapcmp(x, y));
    }

    res = combine(res, cap_zero_comparable <=> rhs.cap_zero_comparable);
    res = combine(res, cap_observed_boolean <=> rhs.cap_observed_boolean);
    res = combine(res, mapcmp(cap_upper_bound_sizes, rhs.cap_upper_bound_sizes));
    res = combine(res, mapcmp(cap_copy_sizes, rhs.cap_copy_sizes));
    res = combine(res, mapcmp(cap_integer_ops, rhs.cap_integer_ops));
    res = combine(res, mapcmp(cap_boolean_ops, rhs.cap_boolean_ops));
    res = combine(res, mapcmp(cap_float_ops, rhs.cap_float_ops));
    return res;
  }

  /// Add in capabilities of `self` and `other`.
  CapabilityVec add(const CapabilityVec &other) const
  {
    auto mapadd = [](const auto &x, const auto &y) {
      std::map<std::remove_const_t<decltype(x.begin()->first)>, uint64_t> ret;
      for (const auto &[k, v] : x) ret[k] += v;
      for (const auto &[k, v] : y) ret[k] += v;
      return ret;
    };

    CapabilityVec out;
    out.cap_is_pointer = cap_is_pointer + other.cap_is_pointer;
    out.cap_is_code = cap_is_code + other.cap_is_code;
    out.cap_zero_comparable = cap_zero_comparable + other.cap_zero_comparable;
    out.cap_observed_boolean = cap_observed_boolean + other.cap_observed_boolean;
    out.cap_upper_bound_sizes = mapadd(cap_upper_bound_sizes, other.cap_upper_bound_sizes);
    out.cap_copy_sizes = mapadd(cap_copy_sizes, other.cap_copy_sizes);
    out.cap_integer_ops = mapadd(cap_integer_ops, other.cap_integer_ops);
    out.cap_boolean_ops = mapadd(cap_boolean_ops, other.cap_boolean_ops);
    out.cap_float_ops = mapadd(cap_float_ops, other.cap_float_ops);
    return out;
  }

  /// Subtract capabilities of `rhs` from `self`. Returns nullopt if the
  /// subtraction would leave negative counts.
  std::optional<CapabilityVec> sub(const CapabilityVec &rhs) const
  {
    if (!rhs.is_smaller_type_than(*this)) {
      return std::nullopt;
    }
    CapabilityVec out;
    out.cap_is_pointer = cap_is_pointer - rhs.cap_is_pointer;
    auto mapsub_uint64 = [](const std::map<size_t, uint64_t> &x,
                            const std::map<size_t, uint64_t> &y)
        -> std::optional<std::map<size_t, uint64_t>> {
      std::map<size_t, uint64_t> ret;
      for (const auto &[k, v] : x) ret[k] = v;
      for (const auto &[k, v] : y) {
        auto it = ret.find(k);
        if (it == ret.end()) return std::nullopt;
        if (it->second < v) return std::nullopt;
        it->second -= v;
      }
      return ret;
    };
    auto mapsub_pair = [](auto x, auto y) -> std::optional<decltype(x)> {
      decltype(x) ret = x;
      for (const auto &[k, v] : y) {
        auto it = ret.find(k);
        if (it == ret.end()) return std::nullopt;
        if (it->second < v) return std::nullopt;
        it->second -= v;
      }
      return ret;
    };
    out.cap_is_code = cap_is_code - rhs.cap_is_code;
    out.cap_zero_comparable = cap_zero_comparable - rhs.cap_zero_comparable;
    out.cap_observed_boolean = cap_observed_boolean - rhs.cap_observed_boolean;
    auto m1 = mapsub_pair(cap_upper_bound_sizes, rhs.cap_upper_bound_sizes);
    if (!m1.has_value()) return std::nullopt;
    out.cap_upper_bound_sizes = *m1;
    auto m2 = mapsub_uint64(cap_copy_sizes, rhs.cap_copy_sizes);
    if (!m2.has_value()) return std::nullopt;
    out.cap_copy_sizes = *m2;
    auto m3 = mapsub_pair(cap_integer_ops, rhs.cap_integer_ops);
    if (!m3.has_value()) return std::nullopt;
    out.cap_integer_ops = *m3;
    auto m4 = mapsub_pair(cap_boolean_ops, rhs.cap_boolean_ops);
    if (!m4.has_value()) return std::nullopt;
    out.cap_boolean_ops = *m4;
    auto m5 = mapsub_pair(cap_float_ops, rhs.cap_float_ops);
    if (!m5.has_value()) return std::nullopt;
    out.cap_float_ops = *m5;
    return out;
  }

  /// Normalize to a standard representation.
  CapabilityVec normalize() const
  {
    if (!config().allow_type_rounding_based_on_upper_bound_size) {
      assert(cap_upper_bound_sizes.empty());
    }
    auto mapnorm = [](const auto &x) {
      std::map<std::remove_const_t<decltype(x.begin()->first)>, uint64_t> ret;
      for (const auto &[k, v] : x) {
        if (v > 0)
          ret[k] = 1;
      }
      return ret;
    };

    CapabilityVec out;
    out.cap_is_pointer = std::min<uint64_t>(cap_is_pointer, 1);
    out.cap_is_code = std::min<uint64_t>(cap_is_code, 1);
    out.cap_zero_comparable = std::min<uint64_t>(cap_zero_comparable, 1);
    out.cap_observed_boolean = std::min<uint64_t>(cap_observed_boolean, 1);
    out.cap_upper_bound_sizes = mapnorm(cap_upper_bound_sizes);
    out.cap_copy_sizes = mapnorm(cap_copy_sizes);
    out.cap_integer_ops = mapnorm(cap_integer_ops);
    out.cap_boolean_ops = mapnorm(cap_boolean_ops);
    out.cap_float_ops = mapnorm(cap_float_ops);
    return out;
  }

  /// Convert from a structural type to a capability vector.
  static CapabilityVec from_structural_type(const StructuralType &stype)
  {
    CapabilityVec out;
    if (config().allow_type_rounding_based_on_upper_bound_size) {
      if (stype.upper_bound_size.has_value()) {
        out.cap_upper_bound_sizes[std::make_pair(*stype.upper_bound_size, size_t{0})] = 1;
      }
    }
    for (size_t s : stype.copy_sizes) {
      out.cap_copy_sizes[s] = 1;
    }
    for (const auto &[op, sz] : stype.integer_ops) {
      out.cap_integer_ops[{op, sz}] = 1;
    }
    for (const auto &[op, sz] : stype.boolean_ops) {
      out.cap_boolean_ops[{op, sz}] = 1;
    }
    for (const auto &[op, sz] : stype.float_ops) {
      out.cap_float_ops[{op, sz}] = 1;
    }
    out.cap_is_pointer = stype.pointer_to.has_value() ? 1 : 0;
    out.cap_is_code = stype.observed_code ? 1 : 0;
    out.cap_zero_comparable = stype.zero_comparable ? 1 : 0;
    out.cap_observed_boolean = stype.observed_boolean ? 1 : 0;
    return out;
  }

  /// Apply `self`'s capabilities to the structural type `stype`.
  void apply_to_structural_type(StructuralType &stype) const
  {
    for (const auto &[sz_pair, v] : cap_upper_bound_sizes) {
      assert(v == 1);
      size_t sz = sz_pair.first;
      if (stype.upper_bound_size.has_value()) {
        if (*stype.upper_bound_size != sz) {
          log::debug("Got non-equal upper bound size",
                     {{"in_type", *stype.upper_bound_size}, {"in_vec", sz}});
        }
      } else {
        stype.upper_bound_size = sz;
      }
    }
    for (const auto &[sz, v] : cap_copy_sizes) {
      assert(v == 1);
      stype.copy_sizes.insert(sz);
    }
    for (const auto &[os, v] : cap_integer_ops) {
      assert(v == 1);
      stype.integer_ops.insert(os);
    }
    for (const auto &[os, v] : cap_boolean_ops) {
      assert(v == 1);
      stype.boolean_ops.insert(os);
    }
    for (const auto &[os, v] : cap_float_ops) {
      assert(v == 1);
      stype.float_ops.insert(os);
    }

    if (cap_is_pointer > 0) {
      if (!stype.pointer_to.has_value()) {
        log::error("Pointerness failure", {});
        TREX_CHECK(false, "Pointerness failure.");
      }
    }
    if (cap_zero_comparable > 0) {
      stype.zero_comparable = true;
    }
    if (cap_observed_boolean > 0) {
      stype.observed_boolean = true;
    }
    if (cap_is_code > 0) {
      stype.observed_code = true;
    }
  }
};

/// Every entry in `allowed_primitives` must be a primitive.
void assert_is_primitive(const StructuralType &stype)
{
  if (stype.colocated_struct_fields.empty() && !stype.observed_array
      && !stype.is_type_for_il_constant_variable) {
    return;
  }
  TREX_CHECK(false, "Found non-primitive type");
}

} // namespace

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// round_up — public wrapper, delegates to anonymous-namespace impl.
// ---------------------------------------------------------------------------
namespace {
IndexMap<std::pair<StructuralType, unordered::UnorderedSet<RoundedIdx>>>
round_up_impl(const Container<StructuralType> &stypes,
              const std::vector<StructuralType> &allowed_primitives,
               const std::vector<std::string> &allowed_primitives_names)
{
  for (const StructuralType &p : allowed_primitives) {
    assert_is_primitive(p);
  }

  std::vector<CapabilityVec> matrix_a;
  matrix_a.reserve(allowed_primitives.size());
  for (const StructuralType &p : allowed_primitives) {
    matrix_a.push_back(CapabilityVec::from_structural_type(p));
  }

  std::vector<size_t> expensiveness_sort(allowed_primitives.size());
  for (size_t i = 0; i < expensiveness_sort.size(); ++i)
    expensiveness_sort[i] = i;
  std::stable_sort(expensiveness_sort.begin(), expensiveness_sort.end(),
                   [&](size_t i, size_t j) {
                     return matrix_a[i].compare_expensiveness_to(matrix_a[j])
                         == std::strong_ordering::less;
                   });

  TREX_CHECK(!matrix_a.empty(), "round_up: at least one allowed primitive required");
  CapabilityVec initial_vec = matrix_a[0];
  for (size_t i = 1; i < matrix_a.size(); ++i) {
    initial_vec = initial_vec.add(matrix_a[i]);
  }

  IndexMap<std::pair<StructuralType, unordered::UnorderedSet<RoundedIdx>>> ret;

  for (const Index &idx : stypes.currently_alive_canon_indices_iter()) {
    const StructuralType &stype = stypes.get(idx);
    CapabilityVec capvec = CapabilityVec::from_structural_type(stype);
    CapabilityVec roundedvec = initial_vec;
    ret.insert(idx, {stype, unordered::UnorderedSet<RoundedIdx>{}});

    if (!capvec.is_smaller_type_than(initial_vec)) {
      std::set<size_t> capvec_sizes;
      for (const auto &[k, _] : capvec.cap_copy_sizes)
        capvec_sizes.insert(k);
      std::set<size_t> initvec_sizes;
      for (const auto &[k, _] : initial_vec.cap_copy_sizes)
        initvec_sizes.insert(k);
      std::vector<size_t> extra_sizes;
      std::set_difference(capvec_sizes.begin(), capvec_sizes.end(),
                          initvec_sizes.begin(), initvec_sizes.end(),
                          std::back_inserter(extra_sizes));
      log::trace("Found padding copy sizes",
                 {{"initvec_sizes", 0}, {"capvec_sizes", 0}, {"extra_sizes", 0}});
      for (size_t sz : extra_sizes) {
        ret.get_mut(idx)->second.insert(RoundedIdx::padding(sz));
        capvec.cap_copy_sizes.erase(sz);
      }

      std::set<std::pair<size_t, size_t>> capvec_ubs;
      for (const auto &[k, _] : capvec.cap_upper_bound_sizes)
        capvec_ubs.insert(k);
      std::set<std::pair<size_t, size_t>> initvec_ubs;
      for (const auto &[k, _] : initial_vec.cap_upper_bound_sizes)
        initvec_ubs.insert(k);
      std::vector<std::pair<size_t, size_t>> extra_ubs;
      std::set_difference(capvec_ubs.begin(), capvec_ubs.end(),
                          initvec_ubs.begin(), initvec_ubs.end(),
                          std::back_inserter(extra_ubs));
      log::trace("Found padding upper-bound sizes",
                 {{"initvec_sizes", 0}, {"capvec_sizes", 0}, {"extra_sizes", 0}});
      for (const auto &p : extra_ubs) {
        ret.get_mut(idx)->second.insert(RoundedIdx::padding(p.first));
        capvec.cap_upper_bound_sizes.erase(p);
      }

      if (!capvec.is_smaller_type_than(initial_vec)) {
        log::debug("Union of primitives is not universe",
                   {{"stype_idx", (uint64_t)idx.idx}});
      }
    }

    log::trace("Rounding", {{"stype_idx", (uint64_t)idx.idx}});

    for (auto it = expensiveness_sort.rbegin(); it != expensiveness_sort.rend(); ++it) {
      size_t i = *it;
      std::optional<CapabilityVec> maybe_newvec = roundedvec.sub(matrix_a[i]);
      bool is_deletable;
      CapabilityVec newvec;
      if (maybe_newvec.has_value()) {
        is_deletable = capvec.is_smaller_type_than(*maybe_newvec);
        newvec = std::move(*maybe_newvec);
      } else {
        is_deletable = false;
        newvec = roundedvec;
      }
      if (is_deletable) {
        log::trace("Deleted", {{"prim", allowed_primitives_names[i]}});
        roundedvec = std::move(newvec);
      } else {
        log::trace("Non deletable", {{"prim", allowed_primitives_names[i]}});
        ret.get_mut(idx)->second.insert(
            RoundedIdx::primitive(i, allowed_primitives_names[i]));
      }
    }

    log::trace("Rounded", {{"stype_idx", (uint64_t)idx.idx}});

    if (roundedvec.cap_is_pointer > 0 && !stype.pointer_to.has_value()) {
      log::debug("Pointerness inconsistency in rounding",
                 {{"stype_idx", (uint64_t)idx.idx}});
    }

    roundedvec.normalize().apply_to_structural_type(ret.get_mut(idx)->first);
  }

  return ret;
}
} // namespace

IndexMap<std::pair<StructuralType, unordered::UnorderedSet<RoundedIdx>>>
round_up(const Container<StructuralType> &stypes,
         const std::vector<StructuralType> &allowed_primitives,
         const std::vector<std::string> &allowed_primitives_names)
{
  return round_up_impl(stypes, allowed_primitives, allowed_primitives_names);
}

// ---------------------------------------------------------------------------
// round_up_to_c_types
// ---------------------------------------------------------------------------
void round_up_to_c_types(Container<StructuralType> &stypes)
{
  auto [c_types_names, c_types_vec]
      = c_types::structural_types_for_all_primitive_c_types();
  std::vector<std::string> c_types_names_v(c_types_names.begin(), c_types_names.end());
  std::vector<StructuralType> c_types_stypes(c_types_vec.begin(), c_types_vec.end());

  auto rounding = round_up(stypes, c_types_stypes, c_types_names_v);


  for (auto entry : std::move(rounding).into_iter()) {
    auto &idx = entry.first;
    auto &pair = entry.second;
    StructuralType &stype = pair.first;
    auto &hm = pair.second;
    if (config().round_up_undefined_n_to_integer) {
      auto undefineds_map_name = c_types::undefineds_to_integers_map();
      if (hm.len() == 1) {
        auto it = hm.iter().begin();
        if (it->kind == RoundedIdx::Kind::Primitive) {
          auto find = undefineds_map_name.find(it->name);
          if (find != undefineds_map_name.end()) {
            const std::string &value_tn = find->second;
            auto pos = std::find(c_types_names_v.begin(), c_types_names_v.end(), value_tn);
            if (pos != c_types_names_v.end()) {
              stype = c_types_stypes[static_cast<size_t>(pos - c_types_names_v.begin())];
            }
          }
        }
      }
    }

    // Rewrite 2: signed/unsigned collapse.
    if (config().collapse_union_of_signed_and_unsigned_ints) {
      if (hm.len() == 2) {
        std::vector<std::string> prim_names;
        for (const auto &ri : hm.iter()) {
          if (ri.kind == RoundedIdx::Kind::Primitive) {
            prim_names.push_back(ri.name);
          }
        }
        if (prim_names.size() == 2) {
          auto collapse = c_types::signed_unsigned_collapse_target();
          std::optional<std::string> target;
          auto it0 = collapse.find(prim_names[0]);
          auto it1 = collapse.find(prim_names[1]);
          if (it0 != collapse.end() && it1 == collapse.end() && it0->second == prim_names[1]) {
            target = prim_names[1];
          } else if (it1 != collapse.end() && it0 == collapse.end()
                     && it1->second == prim_names[0]) {
            target = prim_names[0];
          }
          if (target.has_value()) {
            auto pos = std::find(c_types_names_v.begin(), c_types_names_v.end(), *target);
            if (pos != c_types_names_v.end()) {
              stype = c_types_stypes[static_cast<size_t>(pos - c_types_names_v.begin())];
            }
          }
        }
      }
    }

    stypes.get_mut(idx) = std::move(stype);
  }
}

// ---------------------------------------------------------------------------
// recognize_union_of_c_primitives
// ---------------------------------------------------------------------------
std::set<std::string> recognize_union_of_c_primitives(const StructuralType &stype)
{
  auto [c_types_names, c_types_vec]
      = c_types::structural_types_for_all_primitive_c_types();
  std::vector<std::string> c_types_names_v(c_types_names.begin(), c_types_names.end());
  std::vector<StructuralType> c_types_stypes(c_types_vec.begin(), c_types_vec.end());

  if (!stype.refers_to().empty()) {
    return {};
  }

  Container<StructuralType> stypes;
  Index idx = stypes.insert(stype);

  auto rounding = round_up(stypes, c_types_stypes, c_types_names_v);
  const auto *pair = rounding.get(idx);
  std::set<std::string> out;
  if (pair != nullptr) {
    for (const auto &ri : pair->second.iter()) {
      out.insert(ri.to_string());
    }
  }
  return out;
}

} // namespace trex