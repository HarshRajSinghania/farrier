/**
 * Landing pages for what people search for ("F5 certificate automation", "47-day certificates"...).
 * One entry per page under /solutions/<slug>/. Every claim here must hold in the code: link the doc that
 * proves it. Keep titles under ~60 characters and descriptions under ~155 for search snippets.
 */
export type Solution = {
  slug: string;
  title: string; // <title> and H1 source; the page adds " · Farrier"
  h1: string;
  description: string;
  keywords: string[];
  problem: string;
  steps: { title: string; body: string }[];
  points: string[];
  faq: [string, string][];
  docs: { href: string; label: string };
};

export const SOLUTIONS: Solution[] = [
  {
    slug: "f5-big-ip-certificate-automation",
    title: "F5 BIG-IP certificate automation",
    h1: "Automatic certificate renewal for F5 BIG-IP",
    description:
      "Renew and deploy TLS certificates on F5 BIG-IP over iControl REST: new crypto objects, profile switch, live verification and automatic rollback. Open source.",
    keywords: ["F5 certificate automation", "BIG-IP certificate renewal", "iControl REST certificate", "F5 Let's Encrypt"],
    problem:
      "A BIG-IP cannot run an ACME client, so its client-ssl profiles are renewed by hand: export a CSR, wait for the CA, upload, swap the profile, hope nothing breaks. With certificate lifetimes falling to 47 days, that becomes a job every few weeks per virtual server.",
    steps: [
      { title: "Discover", body: "Farrier scans your ranges, finds every virtual server's certificate and when it expires." },
      { title: "Issue", body: "It requests the certificate from your CA (Let's Encrypt, DigiCert, Sectigo, AWS, a private CA) and answers DNS-01 through your DNS, so the BIG-IP needs no internet access." },
      { title: "Deploy", body: "Over iControl REST it uploads the key and chain as new crypto objects, never overwriting the live ones, repoints the client-ssl profile and saves the config." },
      { title: "Verify or roll back", body: "It handshakes with every virtual address to confirm the new certificate is served, and switches the profile back if it is not." },
    ],
    points: [
      "Agentless: one API user with certificate and profile rights, nothing installed on the BIG-IP",
      "Renewals inside your change windows, with a daily cap so a hundred VIPs don't change at once",
      "Old objects kept for audit; ServiceNow or Jira tickets opened and closed for each change",
    ],
    faq: [
      ["Does the BIG-IP need internet access?", "No. Farrier proves domain control through DNS-01 and reaches the BIG-IP only on its management interface."],
      ["What happens if the new certificate breaks something?", "The previous certificate objects stay installed. If a virtual address does not serve the new certificate, Farrier points the profile back."],
      ["Which BIG-IP rights does it need?", "An iControl REST user that can manage certificates and edit the client-ssl profiles you hand to Farrier."],
    ],
    docs: { href: "/docs/connectors#f5", label: "F5 connector reference" },
  },
  {
    slug: "fortigate-certificate-automation",
    title: "FortiGate certificate automation",
    h1: "Automatic certificate renewal for FortiGate",
    description:
      "Renew FortiGate SSL-VPN, admin GUI and policy certificates automatically through the FortiOS REST API, with live verification and rollback. Open source.",
    keywords: ["FortiGate certificate renewal", "FortiGate Let's Encrypt", "SSL VPN certificate automation", "FortiOS REST API certificate"],
    problem:
      "FortiGate certificates for SSL-VPN portals and the admin GUI are usually renewed by hand from a calendar reminder. A missed one locks remote users out on the day it expires.",
    steps: [
      { title: "Discover", body: "Farrier finds the certificate each FortiGate serves and tracks its expiry." },
      { title: "Issue", body: "It gets the certificate from your CA through DNS-01, so the firewall exposes nothing new." },
      { title: "Deploy", body: "It imports the certificate through the FortiOS REST API and binds it to SSL-VPN, the admin GUI or any setting that references a certificate." },
      { title: "Verify or roll back", body: "It confirms the new certificate is live and restores the previous binding if it is not." },
    ],
    points: [
      "One REST API admin token, scoped to what it binds; VDOMs supported",
      "Change windows and daily caps per device class",
      "Alerts to Slack, Teams, email or a webhook on every outcome",
    ],
    faq: [
      ["Can it renew the SSL-VPN certificate?", "Yes. Set bind to sslvpn; admin binds the GUI certificate, and any cmdb path and field covers the rest."],
      ["Does it support multiple VDOMs?", "Yes, set vdom on the endpoint."],
    ],
    docs: { href: "/docs/connectors#fortigate", label: "FortiGate connector reference" },
  },
  {
    slug: "palo-alto-certificate-automation",
    title: "Palo Alto PAN-OS certificate automation",
    h1: "Automatic certificate renewal for Palo Alto firewalls",
    description:
      "Renew GlobalProtect and SSL/TLS service profile certificates on PAN-OS automatically: import, repoint, commit, verify, roll back. Open source and agentless.",
    keywords: ["Palo Alto certificate renewal", "GlobalProtect certificate", "PAN-OS certificate automation", "PAN-OS XML API"],
    problem:
      "GlobalProtect portals and gateways need a valid certificate at all times. Renewing one means importing a keypair, editing a service profile and committing, on every firewall.",
    steps: [
      { title: "Issue", body: "Farrier requests the certificate from your CA through DNS-01." },
      { title: "Import", body: "It imports the keypair under a new name through the PAN-OS XML API, so the live one is untouched." },
      { title: "Switch and commit", body: "It points the SSL/TLS service profile at the new certificate and commits." },
      { title: "Verify or roll back", body: "It checks the portal serves the new certificate, and points the profile back and commits if not." },
    ],
    points: [
      "One API key; nothing installed on the firewall",
      "Commits only inside your change windows",
      "Every step logged with the commit job, for the change record",
    ],
    faq: [
      ["Does it work with GlobalProtect?", "Yes. Portals and gateways use SSL/TLS service profiles, which is what Farrier switches."],
      ["Does it use Panorama?", "It talks to each firewall's XML API; give it the management address of each one."],
    ],
    docs: { href: "/docs/connectors#panos", label: "PAN-OS connector reference" },
  },
  {
    slug: "47-day-certificate-lifetime",
    title: "Prepare for 47-day TLS certificates",
    h1: "47-day certificates: renew everything automatically",
    description:
      "Public TLS certificate lifetimes fall to 200 days in 2026, 100 in 2027 and 47 in 2029. See the renewal workload and automate it, including appliances ACME can't reach.",
    keywords: ["47-day certificates", "SC-081", "certificate lifetime reduction", "CA/B Forum 47 days", "200-day certificates"],
    problem:
      "The CA/Browser Forum's ballot SC-081 cuts the maximum public certificate lifetime to 200 days from March 2026, 100 days from March 2027 and 47 days from March 2029. Every certificate renewed once a year today will need eight renewals a year, and domain validation can be reused for only 10 days.",
    steps: [
      { title: "Measure", body: "farrier forecast shows how many renewals per week your estate needs under each step of the schedule, and the hours that costs by hand." },
      { title: "Rehearse", body: "farrier demo --simulate-date 2029-03-15 runs your workflow with 47-day certificates today." },
      { title: "Automate", body: "Servers, keystores, F5, FortiGate and PAN-OS renew without people; everything else gets a ready change pack and a ticket." },
      { title: "Prove it", body: "Each renewal is verified live on the device, so a missed expiry shows up as an alert, not an outage." },
    ],
    points: [
      "Renewal timing follows the certificate's real lifetime and the CA's ARI window (RFC 9773)",
      "Change windows and daily caps spread the work so no team gets 300 changes on one night",
      "Works with Let's Encrypt's 6-day short-lived profile as well",
    ],
    faq: [
      ["When do the shorter lifetimes start?", "200 days from 15 March 2026, 100 days from 15 March 2027 and 47 days from 15 March 2029 (CA/B Forum SC-081)."],
      ["Do private certificates have to follow it?", "No, the schedule covers publicly trusted certificates. Farrier's private CA follows it by default so you can rehearse; set lifetime_days to change that."],
    ],
    docs: { href: "/docs/concepts", label: "How renewals are planned" },
  },
  {
    slug: "aws-certificate-manager-acme",
    title: "AWS Certificate Manager ACME automation",
    h1: "AWS Certificate Manager ACME, end to end",
    description:
      "Create ACM ACME endpoints, prevalidate domains, manage EAB credentials and auto-renew ACM's 45-day public certificates on any device, from one open-source tool.",
    keywords: ["ACM ACME", "AWS Certificate Manager ACME", "ACM external account binding", "ACM exportable certificates"],
    problem:
      "ACM's managed ACME endpoint issues public certificates to any ACME client, but someone still has to create endpoints, keep domain validations healthy, hand out EAB credentials and renew 45-day certificates on servers and appliances.",
    steps: [
      { title: "Endpoint", body: "farrier acm endpoint create makes a PRE_APPROVED endpoint and prints its directory URL." },
      { title: "Domains", body: "farrier acm domain add prevalidates a domain once; with a Route 53 zone ACM writes the CNAME itself." },
      { title: "Credentials", body: "farrier acm eab create ties a binding to an IAM role; on AWS the engine reads the key through IAM, so no secret is stored." },
      { title: "Renew", body: "The aws-acm issuer renews every 45-day certificate and deploys it to servers, keystores and appliances." },
    ],
    points: [
      "No DNS-01 at issuance time: names are authorized on the endpoint",
      "Runs on ECS, EKS or EC2 with the platform's IAM role; on GKE, AKS or on premises with stored credentials",
      "Terraform grants the engine only DescribeAcmeEndpoint and GetAcmeExternalAccountBindingCredentials",
    ],
    faq: [
      ["Do other ACME clients work with the same endpoint?", "Yes. farrier acm eab credentials prints the key ID and HMAC key for cert-manager, Certbot or any ACME client."],
      ["What happens to a name the endpoint does not allow?", "The order fails with a clear message to add the domain with farrier acm domain add."],
    ],
    docs: { href: "/docs/configuration#aws-certificate-manager-managed-acme", label: "ACM setup guide" },
  },
  {
    slug: "private-ca-certificate-automation",
    title: "AWS Private CA and Google CAS automation",
    h1: "Private certificates from AWS Private CA or Google CAS, renewed automatically",
    description:
      "Issue internal TLS certificates from AWS Private CA or Google Certificate Authority Service and deploy them to servers, keystores and appliances, renewed on schedule.",
    keywords: ["AWS Private CA automation", "ACM PCA", "Google Certificate Authority Service", "private certificate renewal"],
    problem:
      "A cloud private CA signs certificates, but it does not put them on the F5, the Tomcat keystore or the FortiGate, and it does not renew them there.",
    steps: [
      { title: "Point at the CA", body: "Add an aws_pca issuer with the CA ARN (a CA shared through RAM works) or a gcp_cas issuer with the CA pool." },
      { title: "Issue", body: "Farrier signs a fresh key's CSR through IssueCertificate or caPools.certificates.create; the cloud IAM policy is the authorization." },
      { title: "Deploy and verify", body: "The certificate goes to each endpoint through its connector and is verified live." },
    ],
    points: [
      "Platform identity: IRSA, ECS and EKS task roles, instance profiles, workload identity",
      "Template ARNs and certificate templates for your PKI policy; lifetime per issuer",
      "The dashboard's Test button checks the engine can reach the CA",
    ],
    faq: [
      ["Which signing algorithm is used with AWS Private CA?", "The one that matches the CA's key, read from DescribeCertificateAuthority, unless you set signing_algorithm."],
    ],
    docs: { href: "/docs/configuration", label: "Issuer configuration" },
  },
  {
    slug: "open-source-certificate-lifecycle-management",
    title: "Open-source certificate lifecycle management",
    h1: "Open-source certificate lifecycle management, self-hosted",
    description:
      "Discover, renew, deploy and verify TLS certificates across servers, appliances and clouds. MIT licensed, self-hosted, agentless, with SSO, projects and an audit log.",
    keywords: ["certificate lifecycle management", "open source CLM", "Venafi alternative", "Keyfactor alternative", "certificate management tool"],
    problem:
      "Enterprise certificate platforms take months to roll out and are priced per certificate. Scripts around Certbot don't reach appliances, don't verify what is live and don't leave an audit trail.",
    steps: [
      { title: "Install in one command", body: "install.sh runs the engine and dashboard with Docker; Helm and Terraform cover Kubernetes, AWS, Azure and Google Cloud." },
      { title: "See your estate", body: "Discovery scans your ranges; health grades and a zombie-certificate report show what is at risk." },
      { title: "Automate", body: "Connectors renew servers, keystores and appliances; change packs and ITSM tickets cover the rest." },
      { title: "Govern", body: "OIDC single sign-on with roles, projects per team, alerts and a full activity log." },
    ],
    points: [
      "MIT licensed: no per-certificate pricing, no account, no data leaving your network",
      "Highly available: several replicas with leader election on PostgreSQL or MySQL",
      "Crypto and post-quantum readiness, SSH key inventory and a CycloneDX CBOM in the same tool",
    ],
    faq: [
      ["Is there a hosted version?", "No. Farrier runs on your machines; the dashboard and engine are two containers."],
      ["Can several teams share one install?", "Yes. Projects give each team its own endpoints, SSH keys, alerts and roles, from your SSO groups."],
    ],
    docs: { href: "/docs/install", label: "Install guide" },
  },
];

export const solution = (slug: string) => SOLUTIONS.find((s) => s.slug === slug);
