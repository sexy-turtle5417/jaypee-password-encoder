import { ArgonPasswordEncoder, BcryptPasswordEncoder } from "../src";

describe("ArgonPasswordEncoder", () => {
  describe("encode", () => {
    test("should hash the password", async () => {
      const passwordEncoder = new ArgonPasswordEncoder();
      const plaintextPassword = "password";
      const hashPassword = await passwordEncoder.encode(plaintextPassword);
      expect(plaintextPassword).not.toBe(hashPassword);
    });

    test("should be able to compare passwords", async () => {
      const passwordEncoder = new ArgonPasswordEncoder();
      const plaintextPassword = "password";
      const hashPassword = await passwordEncoder.encode(plaintextPassword);
      expect(
        await passwordEncoder.validate(plaintextPassword, hashPassword)
      ).toBe(true);
    });
  });

  describe("validate", () => {
    test("should return false if the passwords do not match", async () => {
      const passwordEncoder = new ArgonPasswordEncoder();
      const plaintextPassword = "password";
      const plaintextPassword2 = "pass";
      const hashPassword = await passwordEncoder.encode(plaintextPassword);
      expect(
        await passwordEncoder.validate(plaintextPassword2, hashPassword)
      ).toBe(false);
    });

    test("should have different hashsed for same plaintext password", async () => {
      const passwordEncoder = new ArgonPasswordEncoder();
      const password1 = await passwordEncoder.encode("password");
      const password2 = await passwordEncoder.encode("password");
      expect(password1 == password2).not.toBe(true);
    });
  });
});

describe("BcryptPasswordEncoder", () => {
  describe("encode", () => {
    test("should hash the password", async () => {
      const passwordEncoder = new BcryptPasswordEncoder();
      const plaintextPassword = "password";
      const hashPassword = await passwordEncoder.encode(plaintextPassword);
      expect(plaintextPassword).not.toBe(hashPassword);
    });

    test("should be able to compare passwords", async () => {
      const passwordEncoder = new BcryptPasswordEncoder();
      const plaintextPassword = "password";
      const hashPassword = await passwordEncoder.encode(plaintextPassword);
      expect(
        await passwordEncoder.validate(plaintextPassword, hashPassword)
      ).toBe(true);
    });
  });

  describe("validate", () => {
    test("should return false if the passwords do not match", async () => {
      const passwordEncoder = new BcryptPasswordEncoder();
      const plaintextPassword = "password";
      const plaintextPassword2 = "pass";
      const hashPassword = await passwordEncoder.encode(plaintextPassword);
      expect(
        await passwordEncoder.validate(plaintextPassword2, hashPassword)
      ).toBe(false);
    });

    test("should have different hashsed for same plaintext password", async () => {
      const passwordEncoder = new BcryptPasswordEncoder();
      const password1 = await passwordEncoder.encode("password");
      const password2 = await passwordEncoder.encode("password");
      expect(password1 == password2).not.toBe(true);
    });
  });
});
