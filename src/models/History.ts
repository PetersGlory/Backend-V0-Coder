import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../database/config.js';

interface HistoryAttributes {
  id: number;
  user_id: number;
  prompt: string;
  spec: any; // JSON object containing the generated specification
  project_name: string;
  stack_language: string;
  stack_framework: string;
  entities_count: number;
  download_count: number;
  is_favorite: boolean;
  created_at: Date;
  updated_at: Date;
}

interface HistoryCreationAttributes extends Optional<HistoryAttributes, 'id' | 'download_count' | 'is_favorite' | 'created_at' | 'updated_at'> {}

class History extends Model<HistoryAttributes, HistoryCreationAttributes> implements HistoryAttributes {
  public id!: number;
  public user_id!: number;
  public prompt!: string;
  public spec!: any;
  public project_name!: string;
  public stack_language!: string;
  public stack_framework!: string;
  public entities_count!: number;
  public download_count!: number;
  public is_favorite!: boolean;
  public readonly created_at!: Date;
  public readonly updated_at!: Date;
}

History.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'users',
        key: 'id',
      },
    },
    prompt: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    spec: {
      type: DataTypes.JSON,
      allowNull: false,
    },
    project_name: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    stack_language: {
      type: DataTypes.STRING(50),
      allowNull: false,
    },
    stack_framework: {
      type: DataTypes.STRING(50),
      allowNull: false,
    },
    entities_count: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
    },
    download_count: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
    },
    is_favorite: {
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
    modelName: 'History',
    tableName: 'histories',
  }
);

export default History;
