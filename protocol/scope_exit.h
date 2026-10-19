#pragma once

#include <utility>

// Runs a callable when it goes out of scope, unless dismiss() was called.
// Used for cleanup on early returns (closing sockets, deleting partial files).
template <typename F>
class ScopeExit {
public:
    explicit ScopeExit(F f) : f_(std::move(f)) {}
    ~ScopeExit() { if (active_) f_(); }

    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;

    void dismiss() { active_ = false; }

private:
    F f_;
    bool active_ = true;
};

template <typename F>
ScopeExit<F> make_scope_exit(F f) { return ScopeExit<F>(std::move(f)); }
