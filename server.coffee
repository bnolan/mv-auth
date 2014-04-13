express = require("express")
everyauth = require("everyauth")
Skylith = require("skylith")
bodyParser = require("body-parser")
cookieParser = require("cookie-parser")
session = require("express-session")
redis = require("redis")
bcrypt = require("bcrypt")

PORT = process.env.PORT or 3000
ADDRESS = "http://localhost:" + PORT + "/"
PROVIDER_ENDPOINT = ADDRESS + "openid"

# OpenID
skylith = new Skylith(
  providerEndpoint : PROVIDER_ENDPOINT
  checkAuth : checkAuth
)

# Redis
redisClient = redis.createClient()

# store: we're using the default memory store here. Don't use that in production! See http://www.senchalabs.org/connect/session.html#warning
# We use sessions for maintaining state between Skylith calls so this can be quite short

# Inspect 'ax' in the stored context to see which attributes the RP is requesting.
# You SHOULD prompt the user to release these attributes. The suggested flow here is
# to authenticate the user (login), and then on a subsequent page request
# permission to release data.

# Check the login credentials. If you're unhappy do whatever you would do. If you're
# happy then do this...

# Having got permission to release data, form an AX response (this should be done in
# conjunction with the 'ax' attribute in the stored context to see what (if any)
# attributes the Relying Party wants):

# User cancelled authentication
checkAuth = (req, res, allowInteraction, context) ->
  
  # Skylith wants to know if the user is already logged in or not. Check your session/cookies/whatever.
  # * If the user is already logged in, call skylith.completeAuth()
  # * If the user is NOT logged in and allowInteraction is true, store context somewhere (suggest not
  #   in a cookie because it can be quite big), prompt the user to login and when they're done call
  #   skylith.completeAuth()
  # * If the user is NOT logged in and allowInteraction is false, call skylith.rejectAuth()
  
  # This example assumes you're not already logged in
  if allowInteraction
    req.session.skylith = context
    res.redirect 302, "/login"
  else
    # ...

  return


app = express()
app.use bodyParser()
app.use cookieParser()
app.use session(
  key: "s"
  secret: "some big secret for signed cookies"
  cookie:
    signed: true
    httpOnly: true
    maxAge: 1 * 60 * 1000
)

validLogin = (login) ->
  typeof login == 'string' and login.match(/^[a-zA-Z][a-z0-9A-Z_]+$/) and login.length >= 3 and login.length <= 20

validPassword = (password, confirmation) ->
  typeof password == 'string' and password.length >= 3 and password.length <= 20 and password == confirmation

# cryptPassword = (password, salt) ->
#   shasum = crypto.createHash('sha1')
#   shasum.update([password, salt].join('-'))
#   shasum.digest('hex')

everyauth.password
  .getLoginPath('/login') # Uri path to the login page
  .postLoginPath('/login') # Uri path that your login form POSTs to
  .loginView('login')
  
  .authenticate( (login, password) ->
    if !validLogin(login)
      return ["Invalid login"]

    promise = @Promise()

    redisClient.hget "users", login, (err, response) ->
      if response == null
        promise.fulfill(["Invalid login"])
        return

      user = JSON.parse(response)

      if bcrypt.compareSync(password, user.password)
        promise.fulfill user
      else
        promise.fulfill(["Incorrect password"])

    promise
  )

  .loginSuccessRedirect('/')
  .getRegisterPath('/register') # Uri path to the registration page
  .postRegisterPath('/register') # The Uri path that your registration form POSTs to
  .registerView('register')

  .extractExtraRegistrationParams( (req) ->
    { 'password_confirmation': req.body.password_confirmation }
  )

  .validateRegistration( (newUserAttrs) ->
    login = newUserAttrs[@loginKey()].toString()
    password = newUserAttrs.password
    passwordConfirmation = newUserAttrs.password_confirmation

    if !validLogin(login)
      return ["Invalid login #{login}"]

    if !validPassword(password, passwordConfirmation)
      return ["Invalid password"]

    promise = @Promise()
    redisClient.hexists "users", login, (err, response) ->
      if response
        promise.fulfill(["Login already in use"])
      else
        promise.fulfill(null)
    promise
  )

  .registerUser( (newUserAttrs) ->
    login = newUserAttrs[this.loginKey()].toString()
    password = newUserAttrs.password
    salt = bcrypt.genSaltSync(10)

    user = {
      login : login
      password : bcrypt.hashSync(password, salt)
      salt : salt
    }

    promise = @Promise()
    redisClient.hset "users", login, JSON.stringify(user), (err, response) ->
      promise.fulfill(user)
    promise
  )
  .registerSuccessRedirect('/'); # Where to redirect to after a successful registration

app.use everyauth.middleware()
app.use express.static('public')

# app.set 'views', __dirname
app.set 'view engine', 'jade'

app.get '/', (req, res) ->
  res.render('index', { something : [] })

app.use "/openid", skylith.express()

app.get "/login", (req, res, next) ->
  res.type "text/html"
  res.end "<!DOCTYPE html><html><head><title>Login</title></head>" + "<body><h1>Who do you want to be today?</h1>" + "<form method=\"post\">" + "<input type=\"text\" name=\"username\" value=\"Danny\">" + "<button type=\"submit\" name=\"login\">Login</button>" + "<button type=\"submit\" name=\"cancel\">Cancel</button>" + "</form></body></html>"
  return

app.post "/login", (req, res, next) ->
  if "login" of req.body
    axResponse =
      "http://axschema.org/namePerson/friendly": req.body.username
      "http://axschema.org/contact/email": req.body.username.toLowerCase() + "@example.com"
      "http://axschema.org/namePerson": req.body.username + " Smith"

    authResponse =
      context: req.session.skylith
      identity: req.body.username
      ax: axResponse

    skylith.completeAuth req, res, authResponse
  else if "cancel" of req.body
    skylith.rejectAuth req, res, req.session.skylith
  else
    next()
  return

app.listen PORT, ->
  console.log "Running on " + ADDRESS
  return


# TODO - check_immediate isn't implemented yet