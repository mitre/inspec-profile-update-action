control 'SV-214215' do
  title 'The IP address for hidden master authoritative name servers must not appear in the name servers set in the zone database.'
  desc 'A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone. All of the name servers that do appear in the zone database as designated name servers get their zone data from the hidden master via a zone transfer request. In effect, all visible name servers are actually secondary slave servers. This prevents potential attackers from targeting the master name server because its IP address may not appear in the zone database.'
  desc 'check', 'The Infoblox Grid Master should not be configured to service DNS requests from clients.

Navigate to Data Management >> DNS >> Zones.

Review each zone by selecting the zone and clicking "Edit", and selecting the "Name Servers" tab.

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.'
  desc 'fix', 'For each zone that is not in compliance reconfigure the "Name Servers" tab and modify the Grid Master by selecting "Stealth".

When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15430r295908_chk'
  tag severity: 'medium'
  tag gid: 'V-214215'
  tag rid: 'SV-214215r612370_rule'
  tag stig_id: 'IDNS-7X-000880'
  tag gtitle: 'SRG-APP-000516-DNS-000108'
  tag fix_id: 'F-15428r295909_fix'
  tag 'documentable'
  tag legacy: ['SV-83131', 'V-68641']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
