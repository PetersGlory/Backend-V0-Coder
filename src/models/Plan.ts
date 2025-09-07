import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../database/config.js';

export interface PlanAttributes {
  id: number;
  code: string;
  name: string;
  description?: string;
  price_cents: number;
  currency: string;
  interval: 'monthly' | 'yearly';
  request_limit: number;
  priority_support: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface PlanCreationAttributes extends Optional<PlanAttributes, 'id' | 'description' | 'created_at' | 'updated_at'> {}

class Plan extends Model<PlanAttributes, PlanCreationAttributes> implements PlanAttributes {
  public id!: number;
  public code!: string;
  public name!: string;
  public description?: string;
  public price_cents!: number;
  public currency!: string;
  public interval!: 'monthly' | 'yearly';
  public request_limit!: number;
  public priority_support!: boolean;
  public readonly created_at!: Date;
  public readonly updated_at!: Date;
}

Plan.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    code: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    price_cents: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
    },
    currency: {
      type: DataTypes.STRING(10),
      allowNull: false,
      defaultValue: 'USD',
    },
    interval: {
      type: DataTypes.ENUM('monthly', 'yearly'),
      allowNull: false,
      defaultValue: 'monthly',
    },
    request_limit: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 20,
    },
    priority_support: {
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
  },
  {
    sequelize,
    modelName: 'Plan',
    tableName: 'plans',
  }
);

export default Plan;


