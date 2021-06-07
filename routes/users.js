var express = require("express");
var router = express.Router();
var auth = require("../controller/auth");

/* GET users listing. */
router.get("/", function (req, res, next) {
  res.send("respond with a resource");
});

/* GET users listing. */
router.post("/login", function (req, res, next) {
  const username = req.body.username;

  auth.login(username, req.body.password, function (loginResult) {
    console.log("login result", loginResult);

    if (loginResult && !loginResult.code) {
      res.render("users", { username: username });
    } else {
      res.render("index", { error: true });
    }
  });
});

router.post("/authActions", function (req, res, next) {
  console.log("requested action", req.body.authaction);

  if (req.body.authaction && req.body.authaction == "logout") {
    auth.logout(function (logoutResult) {
      console.log("logout result", logoutResult);
      
      if (logoutResult) {
        res.render("index", { error: false });
      } else {
        res.render("users", { username: username });
      }
    });
  }else if(req.body.authaction && req.body.authaction == "refresh"){
    auth.refreshToken(function (refreshResult) {
      console.log("refresh result", refreshResult);
      res.render("users", { operation_executed: true, operation: req.body.authaction, operation_result: refreshResult });

    });
  }else if(req.body.authaction && req.body.authaction == "validate"){
    auth.validateToken(function (validateResult) {
      console.log("validate result", validateResult);
      res.render("users", { operation_executed: true, operation: req.body.authaction, operation_result: validateResult });
    });
  }
});

module.exports = router;
