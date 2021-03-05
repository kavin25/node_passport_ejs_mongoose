const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const passport = require("passport");

// LOGIN PAGE
router.get("/login", (_, res) => res.render("login"));

// REGISTER PAGE
router.get("/register", (req, res) => res.render("register"));

// REGISTER HANDLE
router.post("/register", (req, res) => {
  const { name, email, password, password2 } = req.body;
  const errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({
      msg: "Please fill in all fields",
    });
  }

  if (password !== password2) {
    errors.push({
      msg: "Passwords do not match",
    });
  }

  if (password.length < 6) {
    errors.push({
      msg: "Password should be at least 6 characters long",
    });
  }

  if (errors.length > 0) {
    res.render("register", {
      errors,
      ...req.body,
    });
  } else {
    // VALIDATION PASSED
    User.findOne({ email })
      .then((user) => {
        if (user) {
          errors.push({
            msg: "User with email exists",
          });
          res.render("register", {
            errors,
            ...req.body,
          });
        } else {
          const newUser = new User({
            name,
            email,
            password,
          });

          bcrypt.genSalt(10, (err, salt) =>
            bcrypt.hash(newUser.password, salt, (err, hash) => {
              if (err) throw err;

              newUser.password = hash;
              newUser
                .save()
                .then((_) => {
                  req.flash(
                    "success_msg",
                    "You are now registered and can login"
                  );
                  res.redirect("/users/login");
                })
                .catch((err) => {
                  console.error(err);
                });
            })
          );
        }
      })
      .catch((err) => {
        console.error(err);
      });
  }
});

// LOGIN HANDLER
router.post("/login", (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  })(req, res, next);
});

// LOGOUT HANDLER
router.get("/logout", (req, res) => {
  req.logout();
  req.flash("success_msg", "Logged out successfully");
  res.redirect("/users/login");
});

module.exports = router;
