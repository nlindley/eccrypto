module.exports = {
  extends: ["eslint:recommended", "prettier"],
  parserOptions: {
    ecmaVersion: "latest",
  },
  env: {
    node: true,
    mocha: true,
    es6: true,
  },
};
