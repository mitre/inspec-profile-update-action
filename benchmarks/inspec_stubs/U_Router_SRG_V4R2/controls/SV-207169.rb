control 'SV-207169' do
  title 'The multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to only join multicast groups from sources that have been approved.

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation

If the DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only those multicast groups from sources that have been approved.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7430r382535_chk'
  tag severity: 'medium'
  tag gid: 'V-207169'
  tag rid: 'SV-207169r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000115'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-7430r382536_fix'
  tag 'documentable'
  tag legacy: ['SV-93039', 'V-78333']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
