import Bcrypt from "bcrypt";
import Argon2 from "argon2";

export interface PasswordEncoder {
  encode(plaintextPassword: string): Promise<string>;
  validate(
    plaintextPassword: string,
    encodedPassword: string
  ): Promise<boolean>;
}

export class BcryptPasswordEncoder implements PasswordEncoder {
  encode(plaintextPassword: string): Promise<string> {
    return Bcrypt.hash(plaintextPassword, 10);
  }
  validate(
    plaintextPassword: string,
    encodedPassword: string
  ): Promise<boolean> {
    return Bcrypt.compare(plaintextPassword, encodedPassword);
  }
}

export class ArgonPasswordEncoder implements PasswordEncoder {
  validate(
    plaintextPassword: string,
    encodedPassword: string
  ): Promise<boolean> {
    return Argon2.verify(encodedPassword, plaintextPassword);
  }
  encode(plaintextPassword: string): Promise<string> {
    return Argon2.hash(plaintextPassword);
  }
}
