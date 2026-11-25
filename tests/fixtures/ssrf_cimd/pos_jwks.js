const axios = require("axios");
async function verifyWithJku(token, header) {
  const keys = await axios.get(header.jku);
  return pickKey(keys.data, header.kid);
}
async function discover(issuer) {
  const url = `${issuer}/.well-known/openid-configuration`;
  return (await axios.get(url)).data;
}
