const express = require('express');
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const dotenv = require('dotenv');
const passport = require('passport');
// const Auth0Strategy = require('passport-auth0');
const OAuth2Strategy = require('passport-oauth2');
const refresh = require('passport-oauth2-refresh');
const flash = require('connect-flash');
const nconf = require('nconf');

dotenv.load();

const routes = require('./routes/index');
const user = require('./routes/user');

const config = nconf.env({ separator: '_' }).file('default', {
  file: path.join(path.resolve(__dirname, ''), '/conf/config.json'),
});

// get config from json
const auth = config.get('auth');

// callback for each strategy
const authCallback = function(accessToken, refreshToken, profile, done) {
  if (!process.env.OIDC_USERINFO_URL) {
    return done(null, {
      at: accessToken,
      rt: refreshToken,
      prof: { msg: 'userinfo url was not defined' },
    });
  }
  this._oauth2.get(process.env.OIDC_USERINFO_URL, accessToken, function(
    err,
    body,
    res
  ) {
    if (err) {
      return done(new Error('failed to fetch user profile', err));
    }
    return done(null, {
      at: accessToken,
      rt: refreshToken,
      prof: JSON.parse(body),
    });
  });
};

// oauth2 common URLs
const oauth2Base = process.env.OAUTH2_BASE_URL;

// collection of strategies
const strategies = auth.map(client => {
  return {
    accountId: client.accountId,
    strategy: new OAuth2Strategy(
      {
        authorizationURL: `${oauth2Base}/${client.accountId}/authorize?v=1.0&state=${client.accountId}`,
        tokenURL: `${oauth2Base}/${client.accountId}/token?v=2.0&state=${client.accountId}`,
        clientID: client.clientId,
        clientSecret: client.clientSecret,
        callbackURL: `/api/callback`,
      },
      authCallback
    ),
  };
});

// bind each strategy to passport
strategies.forEach(client => {
  passport.use(`sso-${client.accountId}`, client.strategy);
  refresh.use(`sso-${client.accountId}`, client.strategy);
});

// you can use this section to keep a smaller payload
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  session({
    secret: 'shhhhhhhhh',
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

app.use(flash());

// Handle auth failure error messages
app.use(function(req, res, next) {
  if (req && req.query && req.query.error) {
    req.flash('error', req.query.error);
  }
  if (req && req.query && req.query.error_description) {
    req.flash('error_description', req.query.error_description);
  }
  next();
});

// Check logged in
app.use(function(req, res, next) {
  res.locals.loggedIn = false;
  if (req.session.passport && typeof req.session.passport.user != 'undefined') {
    res.locals.loggedIn = true;
  }
  next();
});

app.use('/', routes);
app.use('/user', user);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err,
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {},
  });
});

module.exports = app;
