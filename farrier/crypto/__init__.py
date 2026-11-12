"""Agentless cryptographic discovery and post-quantum (PQC) readiness.

  tls_wire     ClientHello/ServerHello bytes, built and parsed by hand (pure)
  algorithms   certificate key / signature facts (pure)
  probe        the network probe of one TLS target (bounded by a timeout per connection)
  analysis     PQC status, weak-crypto flags, asset shape and summary (pure)
  cbom         CycloneDX 1.6 CBOM (pure)
  repository   persistence (migration 5)
  service      scan targets, tick re-scan, TLS + SSH asset reads
  certificate  certificate details of an inventory endpoint, from stored observations
"""
