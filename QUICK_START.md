# Quick Start: Fixing Critical Issues

## 🚨 Immediate Action Required

### 1. Fix Authentication Port Bug (CRITICAL)

**Location:** `src/local.rs` - `login()` function

**Problem:** Port `:8443` is lost when constructing login URLs for CRUD operations.

**Quick Fix Steps:**
1. Verify `self.base_url` preserves port when cloned
2. Ensure `base.join(path)` preserves port in URL construction
3. Add explicit port check in `login()` method
4. Test with: `unifictl local networks` (should authenticate correctly)

**Test Command:**
```bash
# Should work without "login failed" error
unifictl local networks
unifictl local wlans
unifictl local firewall-rules
```

---

## 🎯 Next Steps (Priority Order)

1. **Test Watch Mode** - Verify `--watch` flag works correctly
2. **Better Error Messages** - Make CRUD errors actionable
3. **Dry-Run Mode** - Add `--dry-run` to delete commands
4. **Interactive Confirmations** - Add prompts for dangerous operations

---

## 📋 Full Plan

See `IMPROVEMENT_PLAN.md` for complete details on all improvements.
