control 'SV-80821' do
  title 'The Juniper SRX Services Gateway Firewall must only allow inbound communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic enters the Juniper SRX by way of interfaces. Security zones are configured for one or more interfaces with the same security requirements for filtering data packets. A security zone implements a security policy for one or multiple network segments. These policies must be applied to inbound traffic as it crosses the network perimeter and as it crosses internal security domain boundaries.'
  desc 'check', 'Obtain and review the list of authorized sources and destinations. This is usually part of the System Design Specification or Accreditation Package.

Review each of the configured security policies in turn.

[edit]
show security policies <security-policy-name>

If any existing policies allow traffic that is not part of the authorized sources and destinations list, this is a finding.'
  desc 'fix', 'Configure a security policy or screen to each outbound zone to implement continuous monitoring. The following commands configure a security zone called “untrust” that can be used to apply security policy for inbound interfaces that are connected to untrusted networks. This example assumes that interfaces ge-0/0/1 and ge-0/0/2 are connected to untrusted and trusted network segments.

Apply security policy a zone example:

set security zones security-zone untrust interfaces ge-0/0/1.0
set security zones security-zone trust interfaces ge-0/0/2.0
set security policies from-zone trust to-zone untrust policy default-deny match destination-address any
set security policies from-zone trust to-zone untrust policy default-deny then deny'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66331'
  tag rid: 'SV-80821r1_rule'
  tag stig_id: 'JUSX-AG-000126'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-72407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
