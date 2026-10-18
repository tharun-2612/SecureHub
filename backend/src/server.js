require('dotenv').config();

const app = require('./app');
const { connectDatabase } = require('./config/database');

const PORT = process.env.PORT || 5000;

connectDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`SecureHub API server is running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to start SecureHub API server:', error.message);
    process.exit(1);
  });
