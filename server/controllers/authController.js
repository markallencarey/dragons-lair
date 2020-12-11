const bcrypt = require('bcryptjs')

module.exports = {
  register: async (req, res) => {
    const db = req.app.get('db')
    const { username, password, is_admin } = req.body
    
    const [existingUser] = await db.get_user([username])
    if (existingUser) {
      return res.status(409).send('Username taken')
    }

    const salt = bcrypt.genSaltSync(10)
    const hash = bcrypt.hashSync(password, salt)

    const [registeredUser] = await db.register_user([is_admin, username, hash])
    req.session.user = registeredUser
    res.status(201).send(registeredUser)
  },

  login: async (req, res) => {
    const db = req.app.get('db')
    const { username, password } = req.body

    const [existingUser] = await db.get_user([username])

    if (!existingUser) {
      res.status(401).send('User not found. Please register as a new user before logging in.')
    }

    const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)

    if (!isAuthenticated) {
      res.status(403).send('Incorrect password')
    }

    delete existingUser.hash

    req.session.user = existingUser
    res.status(200).send(existingUser)
  },

  logout: async (req, res) => {
    req.session.destroy()
    res.send(200)
  }
}