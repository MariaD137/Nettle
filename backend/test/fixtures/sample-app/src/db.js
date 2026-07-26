// Stub — this fixture app is never actually executed, only statically
// scanned. This file exists so `require("./db")` resolves cleanly if anyone
// ever does try to run it.
module.exports = {
  query(sql, callback) {
    callback(null, []);
  },
};
