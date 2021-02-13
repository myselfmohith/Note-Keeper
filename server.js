const express = require('express');
const mongoose = require('mongoose');
mongoose.connect("mongodb://localhost/ClipBoard", { useUnifiedTopology: true, useNewUrlParser: true });
const UserDB = require('./models/DataBaseSchma');
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('passport-local').Strategy;
const bcrypt = require('bcrypt');


// Passport Login Setup ===============================================

passport.use(new passportLocal((username, password, done) => {
    UserDB.findOne({ username: username }, async (err, user) => {
        if (err) done(err);
        else {
            if (user != null) {
                if (await bcrypt.compare(password, user.password)) done(null, user);
                else done(null, false, { message: 'Wrong Password' });
            } else done(null, false, { message: "User Not Found" });
        }
        return done;
    })
}))

// --------------------------------------------------------------------

// App setup for Express ==============================================

const app = express();
app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.use(require('express-ejs-layouts'));
app.use(session({
    resave: false,
    saveUninitialized: false,
    secret: "I DONT HAVE SECRET😁"
}))
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => {
    done(null, user.id);
})
passport.deserializeUser((id, done) => {
    UserDB.findById(id, (err, user) => {
        done(err, user);
    })
})

// ---------------------------------------------------------------------

// Server functions ====================================================



// ---------------------------------------------------------------------


// App request =========================================================

app.get("/", (req, res) => {
    if (!req.isAuthenticated()) res.redirect('/login');
    else {
        res.render('home',{user:req.user});
    }
});

app.post("/",async (req, res) => {
    await req.user.clips.unshift({
        content: req.body.content,
        date: new Date().toLocaleDateString(),
        title: req.body.title
    })
    await req.user.save();
    res.redirect("/");
});

app.get("/login", (req, res) => {
    if (req.isAuthenticated()) res.redirect('/');
    else res.render('login');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: "/",
    failureRedirect: '/register'
}))


app.get("/logout", (req, res) => {
    req.logOut();
    res.redirect("/login");
})

app.get("/register", (req, res) => {
    if (req.isAuthenticated()) res.redirect('/');
    else res.render('register');
});

app.post("/register", async (req, res) => {
    await UserDB({
        username: req.body.username,
        password: await bcrypt.hash(req.body.password, 10),
        name: req.body.name
    }).save();
    res.redirect("/login");
});

app.get("/delete/:id", async (req, res) => {
    req.user.clips = [...req.user.clips.filter(clip => clip.id != req.params.id)];
    await req.user.save();
    res.redirect("/");
})


// ---------------------------------------------------------------------


app.listen(688);


// __________________________Notes_______________________________________
// 
// Routes - login*2,register*2,home*2
// Initiate Copy function for a href selected
// ______________________________________________________________________