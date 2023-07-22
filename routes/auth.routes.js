const router = require("express").Router();
const bcryptjs = require("bcryptjs");
const User = require("../models/User.model");
const isLoggedIn = require("../middleware/route-guard");
const saltRounds = 10;

router.get("/signup", (req, res) => {
  res.render("auth/signup");
});

router.get("/login", (req, res) => {
  res.render("auth/login");
});

router.get("/main", isLoggedIn, (req, res) => {
  res.render("main");
});

router.get("/private", isLoggedIn, (req, res) => {
  res.render("private");
});

router.post("/signup", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.render("auth/signup", { error: "The fields can't be empty." });
    return;
  }

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => {
      return bcryptjs.hash(password, salt);
    })
    .then((passwordHashed) => {
      return User.create({ username, passwordHashed });
    })
    .then(() => {
      res.redirect("/");
    })
    .catch((err) => {
      if (err.code === 11000) {
        res.render("auth/signup", { error: "The username can't be repeated." });
      }
    });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.render("auth/login", { error: "The fields can't be empty." });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        res.render("auth/login", { error: "Username doesn't exist" });
      } else if (bcryptjs.compareSync(password, user.passwordHashed)) {
        req.session.currentUser = user;
        res.redirect("/");
      } else {
        res.render("auth/login", { error: "Password is incorect" });
      }
    })
    .catch((error) => {
      console.log(error);
    });
});

router.post("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

module.exports = router;
