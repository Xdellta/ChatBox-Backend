const axios = require('axios');
const prisma = require('./prismaClient');

createUsers();

async function createUsers() {
  await prisma.user.deleteMany();

  const users = [];

  for (let i = 0; i < 100; i++) {
    try {
      const response = await axios.get('https://randomuser.me/api/');
      const randomUser = response.data.results[0];

      users.push({
        email: randomUser.email,
        username: randomUser.login.username,
        hashed_password: randomUser.login.salt,
        avatar: randomUser.picture.large,
      });
    } catch (error) {
      console.error('Error while fetching user:', error);
      continue;
    }
  }

  try {
    await prisma.user.createMany({
      data: users,
    });
    console.log('User seeding completed successfully.');
  } catch (error) {
    console.error('Error while creating users in the database:', error);
  }
}