const bcrypt = require("bcryptjs");
const hashedPassword = bcrypt.hashSync("1q2w3e4r!", 10);
console.log(hashedPassword);
