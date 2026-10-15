# Deferred integration validation

The saved demo uses real Tailscale daemons and Headscale on one Docker host. It does not establish behavior with the Tailscale service, native macOS Tailscale installation or independent physical networks.

A later experiment needs:

- A source running a native Tailscale client on an isolated test tailnet.
- An independently hosted Linux subnet router, with console access for recovery.
- A private TCP service in a separate network namespace behind that router, with no alternative source path.

Establish healthy source-to-service and router-to-service TCP first. Collect source/router bundles within 30 seconds, verify the selected router independently, and record versions, routes, policy and time windows. Change one fault at a time: disable forwarding, break only the source's lab-name resolution, or stop only the destination listener. Restore and verify the healthy baseline after every fault.

Keep route selection, policy and destination-listener checks as independent evidence: the collector does not observe them. Different machines on the same Wi-Fi do not establish different uplinks. Independent-network, native Mac, IPv6 and Tailscale-service validation remain unexecuted.

This stage is not required to replay the saved evidence or discuss whether the workflow is useful. No infrastructure has been provisioned for it.
