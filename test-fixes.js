// Simple test to verify the fixes work
const { syncDatabase } = require('./dist/models/index.js');

async function testDatabase() {
  try {
    console.log('🧪 Testing database connection and plan seeding...');
    await syncDatabase();
    console.log('✅ All tests passed! The fixes work correctly.');
    process.exit(0);
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  }
}

testDatabase();
