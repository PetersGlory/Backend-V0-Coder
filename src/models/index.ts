import sequelize from '../database/config.js';
import User from './User.js';
import History from './History.js';
import Plan from './Plan.js';
import Subscription from './Subscription.js';

// Define associations
User.hasMany(History, {
  foreignKey: 'user_id',
  as: 'histories',
});

History.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user',
});

// Subscription associations
User.hasOne(Subscription, {
  foreignKey: 'user_id',
  as: 'subscription',
});

Subscription.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user',
});

Plan.hasMany(Subscription, {
  foreignKey: 'plan_id',
  as: 'subscriptions',
});

Subscription.belongsTo(Plan, {
  foreignKey: 'plan_id',
  as: 'plan',
});

// Sync database
const syncDatabase = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully.');
    
    // Sync all models
    await sequelize.sync({ alter: true });

    // Seed default plans
    const defaultPlans = [
      {
        code: 'free',
        name: 'Free',
        description: 'Basics to try EaseArch. Limited monthly usage.',
        price_cents: 0,
        currency: 'USD',
        interval: 'monthly' as const,
        request_limit: 10,
        priority_support: false,
      },
      {
        code: 'pro',
        name: 'Pro',
        description: 'For individual developers with higher limits.',
        price_cents: 1900,
        currency: 'USD',
        interval: 'monthly' as const,
        request_limit: 200,
        priority_support: true,
      },
      {
        code: 'team',
        name: 'Team',
        description: 'For teams that need more usage and support.',
        price_cents: 4900,
        currency: 'USD',
        interval: 'monthly' as const,
        request_limit: 1000,
        priority_support: true,
      },
    ];
    for (const plan of defaultPlans) {
      await Plan.findOrCreate({ where: { code: plan.code }, defaults: plan });
    }
    console.log('✅ Database synchronized successfully.');
  } catch (error) {
    console.error('❌ Unable to connect to the database:', error);
    throw error;
  }
};

export { User, History, Plan, Subscription, syncDatabase };
export default sequelize;
