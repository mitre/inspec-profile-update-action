control 'SV-15268' do
  title 'The organization must implement a deep packet inspection solution when protecting perimeter boundaries.'
  desc 'Deep packet inspection (DPI) examines the packet beyond the Layer 4 header by examining the payload to identify the application or service. DPI searches for illegal statements, predefined criteria, malformed packets, and malicious code, thereby enabling the IA appliances to make a more informed decision on whether to allow or not allow the packet through. DPI engines can delve into application centric information to allow different applications to be protected in different ways from different threats. Examples of DPI appliances include next-generation firewalls, application layer gateways as well as specific gateways for web, email and SSL traffic.'
  desc 'check', 'Determine which type of solution is used for deep packet inspection at the enclave boundary. Acceptable solutions for meeting this requirement are a deep packet inspection firewall, or a stateful packet inspection firewall in conjunction with any combination of application firewalls or application layer gateways. 

If the organization does not have any implementation of deep packet inspection protecting their network perimeter boundaries, this is a finding.

Exception: If the perimeter security for the enclave or B/C/P/S is provisioned via the JRSS, then this requirement is not applicable.'
  desc 'fix', 'Implement a deep packet inspection solution at the enclave boundaries.  Verify any IA appliances used for deep packet inspection are connected, properly configured, and actively inspecting all ingress and egress network traffic.'
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12658r8_chk'
  tag severity: 'high'
  tag gid: 'V-14642'
  tag rid: 'SV-15268r6_rule'
  tag stig_id: 'NET0365'
  tag gtitle: 'No deep packet inspection.'
  tag fix_id: 'F-14102r9_fix'
  tag 'documentable'
  tag cci: ['CCI-001116']
  tag nist: ['SC-7 (10) (a)']
end
