control 'SV-80895' do
  title 'The Juniper Networks SRX Series Gateway IDPS must block any prohibited mobile code at the enclave boundary when it is detected.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an email attachment or embedded in other file formats not traditionally associated with executable code. 

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To block known prohibited mobile code or approved mobile code that violates permitted usage requirements, the IDPS must implement policy filters, rules, signatures, and anomaly analysis."
  desc 'check', 'From operational mode, enter the following command to verify outbound zones are configured with an IDP policy: 

show security idp policies

If zones bound to the outbound interfaces, including VPN zones, are not configured with policy filters, rules, signatures, and anomaly analysis, this is a finding.'
  desc 'fix', 'To enable IDP services to drop traffic when there is a detection event on a zone based on the IDP policy:

Once the IDP policy is configured, IDP must be enabled on a security policy in order for IDP inspection to be performed.

Keep in mind that IDP inspection will only be performed on the traffic matching the security policies where IDP is enabled.

To enable IDP on a security policy, enter the following command:

set security policies from-zone <FROM ZONE NAME> to-zone <TO ZONE NAME> policy <POLICY
NAME> then permit application-services idp'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67051r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66405'
  tag rid: 'SV-80895r1_rule'
  tag stig_id: 'JUSX-IP-000009'
  tag gtitle: 'SRG-NET-000229-IDPS-00163'
  tag fix_id: 'F-72481r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
