// Shared with site/: keep in step.
/** Names and links the dashboard shows. Forks change these and nothing else. */
import pkg from "../../package.json";

export const site = {
  name: "Farrier",
  github: "https://github.com/gagankarthik/farrier",
  version: pkg.version, // bumped with farrier/__init__.py; the release workflow checks they match
};
