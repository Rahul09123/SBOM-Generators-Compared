"use strict";

const express = require("express");
const { version } = require("lodash");

const app = express();
app.get("/", (_request, response) => {
  response.json({ service: "sbom-controlled-node", lodash: version });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, "0.0.0.0", () => {
  console.log(`controlled-node listening on ${port}`);
});
