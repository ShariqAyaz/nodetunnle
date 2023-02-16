require('dotenv').config();


const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: 'localhost',
  dialect: 'postgres',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
});

// const sequelize = new Sequelize('nodetunnle', 'postgres', 'abc.123', {
//   host: 'localhost',
//   dialect: 'postgres',
// });

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
}, {
  tableName: 'users',
  timestamps: false,
});

const UserToken = sequelize.define('UserToken', {
  id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    primaryKey: true,
    autoIncrement: true,
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    unique: true,
  },
  accessToken: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  ip: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
}, {
  tableName: 'user_token',
  timestamps: false,
});


module.exports = { sequelize, User ,UserToken  };