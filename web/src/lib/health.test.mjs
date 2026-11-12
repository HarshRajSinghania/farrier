import assert from "node:assert/strict";
import { test } from "node:test";
import { classify } from "./health.ts";

const ep = (id, days_left) => ({ id, name: `e${id}`, days_left });

test("each endpoint lands in exactly one severity, worst reason first", () => {
  const g = classify(
    [ep(1, -3), ep(2, 60), ep(3, 10), ep(4, 60), ep(5, 60), ep(6, 60), ep(7, null)],
    [{ endpoint_id: 2, state: "failed" }, { endpoint_id: 4, state: "awaiting_manual" }],
    [{ endpoint_id: 5, severity: "critical", kind: "unexpected_issuer" }, { endpoint_id: 1, severity: "critical", kind: "expired_served" }],
  );
  assert.deepEqual(g.critical.map((i) => i.id), [1, 2, 5]);
  assert.equal(g.critical[0].reason, "Expired 3 days ago");     // expiry wins over the zombie on the same endpoint
  assert.equal(g.critical[1].reason, "Renewal failed");
  assert.deepEqual(g.warning.map((i) => i.id), [3, 4]);
  assert.deepEqual(g.healthy.map((i) => i.id), [6, 7]);
  const total = g.critical.length + g.warning.length + g.healthy.length;
  assert.equal(total, 7);                                        // nobody counted twice
});
