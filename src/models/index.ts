import sequelize from '../database/config';
import User from './User';
import History from './History';

// Define associations
User.hasMany(History, {
  foreignKey: 'user_id',
  as: 'histories',
});

History.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user',
});

// Sync database
const syncDatabase = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully.');
    
    // Sync all models
    await sequelize.sync({ alter: true });
    console.log('✅ Database synchronized successfully.');
  } catch (error) {
    console.error('❌ Unable to connect to the database:', error);
    throw error;
  }
};

export { User, History, syncDatabase };
export default sequelize;
