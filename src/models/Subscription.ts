import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../database/config.js';

export interface SubscriptionAttributes {
  id: number;
  user_id: number;
  plan_id: number;
  status: 'active' | 'canceled' | 'expired' | 'past_due';
  current_period_start: Date;
  current_period_end: Date;
  renews: boolean;
  used_requests: number;
  created_at: Date;
  updated_at: Date;
}

export interface SubscriptionCreationAttributes extends Optional<SubscriptionAttributes, 'id' | 'status' | 'renews' | 'used_requests' | 'current_period_start' | 'current_period_end' | 'created_at' | 'updated_at'> {}

class Subscription extends Model<SubscriptionAttributes, SubscriptionCreationAttributes> {
  // Remove all public field declarations to avoid shadowing Sequelize getters/setters
}

Subscription.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    plan_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    status: {
      type: DataTypes.ENUM('active', 'canceled', 'expired', 'past_due'),
      allowNull: false,
      defaultValue: 'active',
    },
    current_period_start: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW,
    },
    current_period_end: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    },
    renews: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    used_requests: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
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
  },
  {
    sequelize,
    modelName: 'Subscription',
    tableName: 'subscriptions',
  }
);

export default Subscription;


