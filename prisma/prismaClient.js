const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  console.log('Disconnected from the database');
  process.exit(0);
});

module.exports = prisma;