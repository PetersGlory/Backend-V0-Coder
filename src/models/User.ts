import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../database/config.js';
import bcrypt from 'bcryptjs';

interface UserAttributes {
  id: number;
  email: string;
  username: string;
  password: string;
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  is_active: boolean;
  email_verified: boolean;
  last_login?: Date;
  created_at: Date;
  updated_at: Date;
}

interface UserCreationAttributes extends Optional<UserAttributes, 'id' | 'first_name' | 'last_name' | 'avatar_url' | 'is_active' | 'email_verified' | 'last_login' | 'created_at' | 'updated_at'> {}

class User extends Model<UserAttributes, UserCreationAttributes> {
  // Remove all public field declarations to avoid shadowing Sequelize getters/setters

  // Instance methods
  public async validatePassword(password: string): Promise<boolean> {
    return bcrypt.compare(password, (this as any).password);
  }

  public async hashPassword(): Promise<void> {
    if (!(this as any).password) {
      throw new Error('Password is required for hashing');
    }
    (this as any).password = await bcrypt.hash((this as any).password, 12);
  }

  public toJSON(): any {
    const values = Object.assign({}, this.get());
    delete (values as any).password;
    return values;
  }
}

User.init(
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
      },
    },
    username: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
      validate: {
        len: [3, 50],
        isAlphanumeric: true,
      },
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        len: [6, 255],
      },
    },
    first_name: {
      type: DataTypes.STRING(100),
      allowNull: true,
    },
    last_name: {
      type: DataTypes.STRING(100),
      allowNull: true,
    },
    avatar_url: {
      type: DataTypes.STRING(500),
      allowNull: true,
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    email_verified: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
    },
    last_login: {
      type: DataTypes.DATE,
      allowNull: true,
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
    modelName: 'User',
    tableName: 'users',
    hooks: {
      beforeCreate: async (user: User) => {
        await user.hashPassword();
      },
      beforeUpdate: async (user: User) => {
        if ((user as any).changed('password')) {
          await user.hashPassword();
        }
      },
    },
  }
);

export default User;
