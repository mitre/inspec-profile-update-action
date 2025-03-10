control 'SV-45652' do
  title 'The IDPS must block any prohibited mobile code at the enclave boundary when it is detected.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an e-mail attachment or embedded in other file formats not traditionally associated with executable code. 

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To block known prohibited mobile code or approved mobile code that violates permitted usage requirements, the IDPS must implement policy filters, rules, signatures, and anomaly analysis."
  desc 'check', 'Verify the IDPS blocks any prohibited mobile code at the enclave boundary when it is detected.

If the IDPS does not block any prohibited mobile code at the enclave boundary when it is detected, this is a finding.'
  desc 'fix', 'Configure the IDPS to block any prohibited mobile code at the enclave boundary when it is detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-43018r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34743'
  tag rid: 'SV-45652r2_rule'
  tag stig_id: 'SRG-NET-000229-IDPS-00163'
  tag gtitle: 'SRG-NET-000229-IDPS-00163'
  tag fix_id: 'F-39050r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
