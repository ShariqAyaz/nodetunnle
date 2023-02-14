// In models.js
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize('nodetunnle', 'postgres', 'abc.123', {
  host: 'localhost',
  dialect: 'postgres',
});

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    primaryKey: true,
    autoIncrement: true,
  },
  username: {
    type: DataTypes.STRING(35),
    allowNull: false,
    unique: true,
  },
  email: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING(150),
    allowNull: false,
  },
  is_super_user: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
  },
  created_at: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
  },
  updated_at: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW,
  },
  created_by_db_user: {
    type: DataTypes.STRING(50),
    allowNull: false,
  },
}, {
  tableName: 'users',
  timestamps: false,
});

// Define the triggers as class methods on the model
User.addHook('beforeCreate', (user, options) => {
  user.created_by_db_user = 'your_db_user';
});

User.addHook('beforeUpdate', (user, options) => {
  user.updated_at = new Date();
});

module.exports = { sequelize, User };