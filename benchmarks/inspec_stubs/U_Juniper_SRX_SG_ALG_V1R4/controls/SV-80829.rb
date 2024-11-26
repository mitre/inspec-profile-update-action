control 'SV-80829' do
  title 'The Juniper SRX Services Gateway Firewall must continuously monitor all inbound communications traffic for unusual/unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

The Juniper SRX is a highly scalable system which, by default, provides stateful or stateless continuous monitoring when placed in the architecture at either the perimeter or internal boundaries. 

Unusual/unauthorized activities or conditions may include unusual use of unusual protocols or ports and attempted communications from trusted zones to external addresses. 

Interfaces with identical security requirements can be grouped together into a single security zone. By default, once a security policy is applied to a zone, the Juniper SRX continuously monitors the associated zone for unusual/unauthorized activities or conditions based on the firewall filter or screen associated with that zone.'
  desc 'check', 'For each inbound zone, verify a firewall screen or security policy is configured.

[edit]
show security zone
show security policies

If communications traffic for each inbound zone is not configured with a firewall screen and/or security policy, this is not a finding.'
  desc 'fix', 'Configure a security policy or screen to each inbound zone to implement continuous monitoring. The following commands configure a security zone called “untrust” that can be used to apply security policy for inbound interfaces that are connected to untrusted networks. This example assumes that interfaces ge-0/0/1 and ge-0/0/2 are connected to untrusted and trusted network segments.

Apply policy or screen to a zone example:

set security zones security-zone untrust interfaces ge-0/0/1.0
set security zones security-zone trust interfaces ge-0/0/2.0
set security zones security-zone untrust screen untrust-screen
set security policies from-zone untrust to-zone trust policy default-deny match destination-address any
set security policies from-zone untrust to-zone trust policy default-deny then deny'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66985r1_chk'
  tag severity: 'high'
  tag gid: 'V-66339'
  tag rid: 'SV-80829r1_rule'
  tag stig_id: 'JUSX-AG-000144'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-72415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
