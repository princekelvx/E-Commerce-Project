const fs = require("fs");
const util = require("util");
const crypto = require("crypto");
const Repository = require("./repository");

const scrypt = util.promisify(crypto.scrypt);
class UsersRepository extends Repository {
  async comparePasswords(saved, supplied) {
    // const result = saved.split('.');
    // const hashed = result[0]
    // const salt = result[1]

    const [hashed, salt] = saved.split(".");
    const hashSuppliedbuff = await scrypt(supplied, salt, 64);

    return hashed === hashSuppliedbuff.toString("hex");
  }

  async create(attrs) {
    attrs.id = this.randomId();

    const salt = crypto.randomBytes(8).toString("hex");
    const hashed = await scrypt(attrs.password, salt, 64);
    const records = await this.getAll();
    const record = {
      ...attrs,
      password: `${hashed.toString("hex")}.${salt}`,
    };
    records.push(record);
    await this.writeAll(records);

    return record;
  }
}

module.exports = new UsersRepository("users.json");
