#pragma once

// Small RAII helpers over the SQLite C API, shared by the relay's store and the client's message
// history. Header-only: include <sqlite3.h> first (callers link SQLite themselves).

#include <sqlite3.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace sqlitex {

using Bytes = std::vector<uint8_t>;

[[noreturn]] inline void fail(sqlite3* db, const char* what) {
    throw std::runtime_error(std::string("database: ") + what + ": " + (db ? sqlite3_errmsg(db) : "?"));
}

inline void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("database: " + msg);
    }
}

// One prepared statement, bound by position (1-based) and stepped.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) fail(db, "prepare");
    }
    ~Stmt() { sqlite3_finalize(stmt_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& blob(int i, const Bytes& b) {
        static const uint8_t empty = 0;  // never bind NULL for an empty blob
        if (sqlite3_bind_blob(stmt_, i, b.empty() ? &empty : b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            fail(db_, "bind");
        return *this;
    }
    Stmt& i64(int i, int64_t v) {
        if (sqlite3_bind_int64(stmt_, i, v) != SQLITE_OK) fail(db_, "bind");
        return *this;
    }
    // Bound as real TEXT, so it compares equal to SQL string literals such as ''.
    Stmt& text(int i, const std::string& s) {
        if (sqlite3_bind_text(stmt_, i, s.empty() ? "" : s.data(), static_cast<int>(s.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            fail(db_, "bind");
        return *this;
    }

    // True while a row is available; false when done.
    bool step() {
        int rc = sqlite3_step(stmt_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        fail(db_, "step");
    }
    Bytes column_blob(int i) const {
        const void* p = sqlite3_column_blob(stmt_, i);
        int n = sqlite3_column_bytes(stmt_, i);
        if (!p || n <= 0) return {};
        const uint8_t* b = static_cast<const uint8_t*>(p);
        return Bytes(b, b + n);
    }
    std::string column_text(int i) const {
        Bytes b = column_blob(i);
        return std::string(b.begin(), b.end());
    }
    int64_t column_i64(int i) const { return sqlite3_column_int64(stmt_, i); }

private:
    sqlite3* db_;
    sqlite3_stmt* stmt_ = nullptr;
};

// BEGIN IMMEDIATE ... COMMIT, rolled back automatically if commit() isn't reached.
class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) { exec(db_, "BEGIN IMMEDIATE"); }
    ~Transaction() {
        if (open_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    void commit() {
        exec(db_, "COMMIT");
        open_ = false;
    }

private:
    sqlite3* db_;
    bool open_ = true;
};

}  // namespace sqlitex
