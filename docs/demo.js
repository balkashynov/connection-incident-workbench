"use strict";
const cases = {
  "source-only": {label:"SOURCE EVIDENCE ONLY",title:"A timeout leaves several explanations open.",body:"With only the source bundle, the tool does not attribute the failure to forwarding, policy, routing or the service.",limit:"Add the matching router bundle to see what additional evidence can establish."},
  paired: {label:"SOURCE + ROUTER EVIDENCE",title:"Forwarding is disabled. The router can reach the service.",body:"That combination supports a narrower hypothesis: disabled forwarding can explain the source failure if this is the router the route actually uses.",limit:"Route selection, access policy, filtering and return routing remain unverified. The next check is to verify the route, restore forwarding and repeat."},
  recovered: {label:"RECORDED RECOVERY",title:"After forwarding is restored, source TCP connects.",body:"A separate collection after the lab change records a successful source connection to the same explicit destination.",limit:"This is a controlled recovery observation. The analyzer does not automatically compare runs or claim a unique cause. Application health remains untested."},
  healthy: {label:"HEALTHY CONNECTION CONTROL",title:"Source and router both connect to the service.",body:"Before the fault, forwarding is enabled and both explicit-IP TCP checks succeed. This is the control for the tested connection.",limit:"The lab name is supplied by a hosts entry. QueryDNS still fails, so this does not establish Tailscale DNS health."},
  shareable: {label:"PSEUDONYMIZED EXPORT",title:"Keep the relationships. Replace raw identifiers.",body:"The paired incident retains the same findings after export. Identifiers are mapped consistently across both bundles and the analyzer runs again.",limit:"Pseudonymization is not complete anonymization. Topology, ports, timing and platform remain visible; review a report before sharing it."}
};
let request = 0;
function observation(data, role, kind) { return data.bundles.find(b=>b.role===role)?.observations.find(o=>o.kind===kind); }
function outcome(o) {
  if (!o) return "Not collected";
  if (o.kind === "forwarding" && o.state === "observed") return o.facts.enabled ? "Enabled" : "Disabled";
  if (o.kind === "tcp" && o.state === "observed") return "Connected";
  if (o.kind === "peer" && o.state === "observed") return "Peer replied";
  if (o.kind.startsWith("dns") && o.state === "observed") return "Resolved";
  return o.state.replaceAll("_", " ").replace(/^./, c=>c.toUpperCase());
}
async function selectCase() {
  const ticket = ++request;
  const hash = location.hash.slice(1);
  const key = Object.hasOwn(cases, hash) ? hash : "source-only";
  const item = cases[key];
  document.querySelectorAll("[data-case]").forEach(a=>{
    if (a.dataset.case === key) a.setAttribute("aria-current", "true");
    else a.removeAttribute("aria-current");
  });
  for (const [id, text] of [["case-label",item.label],["conclusion-title",item.title],["conclusion-body",item.body],["conclusion-limit",item.limit]]) document.getElementById(id).textContent=text;
  document.getElementById("report-link").href=`demo/${key}.html`;
  document.getElementById("json-link").href=`demo/${key}.json`;
  const status=document.getElementById("load-status");
  const checks=document.getElementById("checks");
  const findings=document.getElementById("finding-list");
  checks.replaceChildren();findings.replaceChildren();status.textContent="Loading saved evidence…";
  try {
    const response=await fetch(`demo/${key}.json`);
    if (!response.ok) throw new Error("Could not load the saved report");
    const data=await response.json();
    if (ticket!==request) return;
    for (const [label, role, kind] of [["Source OS DNS","source","dns_os"],["Source peer ping","source","peer"],["Source → service TCP","source","tcp"],["Router forwarding","router","forwarding"],["Router → service TCP","router","tcp"],["Source Tailscale QueryDNS","source","dns_tailscale"]]) {
      const row=document.createElement("div"),dt=document.createElement("dt"),dd=document.createElement("dd");
      dt.textContent=label;dd.textContent=outcome(observation(data,role,kind));row.append(dt,dd);checks.append(row);
    }
    for (const finding of data.findings) {
      const article=document.createElement("article");article.className="finding";
      const category=document.createElement("p");category.className="kind";category.textContent=finding.category.replaceAll("_"," ");
      const summary=document.createElement("p");summary.textContent=finding.summary;
      const next=document.createElement("p");next.className="next";next.textContent=`Next check: ${finding.next_check}`;
      const rule=document.createElement("code");rule.textContent=finding.rule_id;
      article.append(category,summary,next,rule);findings.append(article);
    }
    status.textContent="Saved observations loaded. No live probes are running.";
  } catch (error) {
    if(ticket!==request)return;
    status.textContent="The saved evidence could not load. You can still open the standalone report using the link above.";
  }
}
window.addEventListener("hashchange",selectCase);
selectCase();
