control 'SV-215796' do
  title 'The BIG-IP Core implementation must continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network crossing  internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy to continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.

If the BIG-IP Core is not configured to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.

Apply ASM policy to the applicable Virtual Server(s) in BIG-IP LTM module to continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16988r291201_chk'
  tag severity: 'medium'
  tag gid: 'V-215796'
  tag rid: 'SV-215796r557356_rule'
  tag stig_id: 'F5BI-LT-000239'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-16986r291202_fix'
  tag 'documentable'
  tag legacy: ['V-60373', 'SV-74803']
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
