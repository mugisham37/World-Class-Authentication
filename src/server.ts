import app from './app';
import { env } from './config/environment';
import { PrismaClient } from '@prisma/client';

// Initialize Prisma client
const prisma = new PrismaClient();

// Get port from environment
const PORT = env.PORT;

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} in ${env.NODE_ENV} mode`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🌐 API base URL: http://localhost:${PORT}/api/${env.API_VERSION}`);
});

// Handle database connection
async function connectToDatabase() {
  try {
    await prisma.$connect();
    console.log('🔌 Connected to database');
  } catch (error) {
    console.error('❌ Failed to connect to database:', error);
    process.exit(1);
  }
}

// Connect to database
connectToDatabase();

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await gracefulShutdown();
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await gracefulShutdown();
});

async function gracefulShutdown() {
  try {
    // Close server
    server.close(() => {
      console.log('Server closed');
    });

    // Disconnect from database
    await prisma.$disconnect();
    console.log('Disconnected from database');

    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
}

export default server;
