control 'SV-214538' do
  title 'The Juniper SRX Services Gateway Firewall must continuously monitor outbound communications traffic for unusual/unauthorized activities or conditions.'
  desc 'If outbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

The Juniper SRX is a highly scalable system which can provide stateful or stateless continuous monitoring when placed in the architecture at either the perimeter or internal boundaries. Unusual/unauthorized activities or conditions may include unusual use of unusual protocols or ports and attempted communications from trusted zones to external addresses.'
  desc 'check', 'For each outbound zone, verify a firewall screen or security policy is configured.

[edit]
show security zones
show security policies

If communications traffic for each outbound zone is not configured with a firewall screen or security policy, this is not a finding.'
  desc 'fix', 'Configure a security policy or screen to each outbound zone to implement continuous monitoring. The following commands configure a security zone called “untrust” that can be used to apply security policy for inbound interfaces that are connected to untrusted networks. This example assumes that interfaces ge-0/0/1 and ge-0/0/2 are connected to untrusted and trusted network segments.

Apply policy or screen to a zone example:

set security zones security-zone untrust interfaces ge-0/0/1.0
set security zones security-zone trust interfaces ge-0/0/2.0
set security zones security-zone untrust screen untrust-screen
set security policies from-zone trust to-zone untrust policy default-deny match destination-address any
set security policies from-zone trust to-zone untrust policy default-deny then deny'
  impact 0.7
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15744r297298_chk'
  tag severity: 'high'
  tag gid: 'V-214538'
  tag rid: 'SV-214538r557389_rule'
  tag stig_id: 'JUSX-AG-000145'
  tag gtitle: 'SRG-NET-000391-ALG-000140'
  tag fix_id: 'F-15742r297299_fix'
  tag 'documentable'
  tag legacy: ['SV-80831', 'V-66341']
  tag cci: ['CCI-002662']
  tag nist: ['SI-4 (4) (b)']
end
