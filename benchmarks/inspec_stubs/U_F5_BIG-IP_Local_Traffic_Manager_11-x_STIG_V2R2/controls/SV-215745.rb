control 'SV-215745' do
  title 'The BIG-IP Core implementation must be configured to monitor inbound traffic for remote access policy compliance when accepting connections to virtual servers.'
  desc "Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

A remote access policy establishes and documents usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed prior to allowing connections to the information systems.

Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS, and webmail). With inbound TLS inspection, the traffic must be inspected prior to being allowed on the enclave's web servers hosting TLS or HTTPS applications. With outbound traffic inspection, traffic must be inspected prior to being forwarded to destinations outside of the enclave, such as external email traffic."
  desc 'check', 'If the BIG-IP Core does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS, and webmail) for virtual servers, this is not applicable.

When intermediary services for remote access communications traffic are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to inspect traffic or forward to a monitoring device for inspection prior to forwarding to inbound destinations.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy to monitor inbound traffic for remote access policy compliance when accepting remote access connections to virtual servers.

If the BIG-IP Core is not configured to monitor inbound traffic for compliance with remote access security policies, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to monitor inbound traffic for remote access policy compliance.

Apply policy to the applicable Virtual Server(s) in the BIG-IP LTM module to monitor inbound traffic for remote access policy compliance when accepting connections to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16937r291048_chk'
  tag severity: 'medium'
  tag gid: 'V-215745'
  tag rid: 'SV-215745r557356_rule'
  tag stig_id: 'F5BI-LT-000031'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-16935r291049_fix'
  tag 'documentable'
  tag legacy: ['V-60271', 'SV-74701']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
