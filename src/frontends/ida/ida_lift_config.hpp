#pragma once

// Microcode maturity level used by the IDA frontend.
//
// The probe action (`trexida:probe`) prints, for the function under the cursor, whether
// gen_microcode() succeeds at each candidate level and how many lvars the result carries.
// The level recorded here is the highest one that returns a non-null mba_t *and*
// a non-empty mba_t::vars (we need lvars: names + IDA base types).
//
// Expected: MMAT_LVARS. Confirm with the probe before trusting S8's variable table.

#include <hexrays.hpp>

namespace trex {
inline constexpr mba_maturity_t IDA_LIFT_MATURITY = MMAT_LVARS;
}
