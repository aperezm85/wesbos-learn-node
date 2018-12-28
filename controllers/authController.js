const passport = require('passport')
const crypto = require('crypto')
const mongoose = require('mongoose')
const User = mongoose.model('User')
const promisify = require('es6-promisify')

exports.login = passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: 'Failed Login!',
  successRedirect: '/',
  successFlash: 'You are now logged in!'
})

exports.logout = (req, res) => {
  req.logout()
  req.flash('success', 'You are now logged out!')
  res.redirect('/')
}

exports.isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    next()
    return
  }
  req.flash('error', 'Opps you must be logged in')
  res.redirect('/login')
}

exports.forgot = async (req, res) => {
  // See if a user exist
  const user = await User.findOne({ email: req.body.email })
  if (!user) {
    req.flash('error', 'A password reset has been mailed to you.')
    return res.redirect('/login')
  }
  // Set reset token and expiry on their account
  user.resetPasswordToken = crypto.randomBytes(20).toString('hex')
  user.resetPasswordExpires = Date.now() + 3600000 // 1 hour from now
  await user.save()
  // send email with token
  const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`
  req.flash('success', `You have beed emailed a password reset link. ${resetURL}`)
  //redirect to login page
  res.redirect('/login')
}

exports.reset = async (req, res) => {
  const token = req.params.token
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: {
      $gt: Date.now()
    }
  })
  if (!user) {
    req.flash('error', 'Password reset is invalid or has expired')
    return redirect('/login')
  }
  res.render('reset', { title: 'Reset your password' })
}

exports.confirmedPasswords = (req, res, next) => {
  if (req.body.password === req.body["password-confirm"]) {
    next()
    return
  } else {
    req.flash('error', 'Passwords do not match!')
    res.redirect('back')
  }
}

exports.update = async (req, res) => {
  const token = req.params.token
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: {
      $gt: Date.now()
    }
  })
  if (!user) {
    req.flash('error', 'Password reset is invalid or has expired')
    return redirect('/login')
  }
  const setPassword = promisify(user.setPassword, user)
  await setPassword(req.body.password)
  user.resetPasswordExpires = undefined
  user.resetPasswordToken = undefined
  const updatedUser = await user.save()
  await req.login(updatedUser)
  req.flash('success', 'Nice! Your password has been reset! You are now logged in')
  res.redirect('/')
}