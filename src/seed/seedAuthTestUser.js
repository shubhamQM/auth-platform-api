const User = require("../models/userManagement/User");

const {
  hashPassword,
} = require("../security/passwordSecurity");

const TEST_USER = {
  userId: "AUTH_TEST_EMP_001",
  tenantId: "TENANT_001",

  firstName: "Auth",
  lastName: "Employee",

  email: "auth.employee@test.local",

  mobile: "9999999999",

  userType: "employee",

  roleIds: [],

  department: "IT",
  designation: "Test Employee",

  isProfileComplete: true,
  createdBySystem: false,

  isActive: true,
};

const TEST_PASSWORD = "AuthTest@123";

async function seedAuthTestUser() {
  try {
    console.log("Creating authentication test employee...");

    // --------------------------------------------------
    // Prevent duplicate test user
    // --------------------------------------------------

    const existingUser = await User.findOne({
      userId: TEST_USER.userId,
    });

    if (existingUser) {
      console.log(
        `Test user already exists: ${TEST_USER.userId}`,
      );

      return;
    }

    // --------------------------------------------------
    // Hash initial employee password
    // --------------------------------------------------

    const passwordHash =
      await hashPassword(TEST_PASSWORD);

    // --------------------------------------------------
    // Create employee
    // --------------------------------------------------

    await User.create({
      ...TEST_USER,
      password: passwordHash,
    });

    console.log("Test employee created successfully.");

    console.log({
      userId: TEST_USER.userId,
      email: TEST_USER.email,
      password: TEST_PASSWORD,
    });
  } catch (error) {
    console.error(
      "Failed to create authentication test employee:",
      error,
    );

    throw error;
  }
}

module.exports = {
  seedAuthTestUser,
};