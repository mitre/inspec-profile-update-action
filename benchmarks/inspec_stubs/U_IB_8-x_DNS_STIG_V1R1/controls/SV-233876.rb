control 'SV-233876' do
  title 'The IP address for hidden master authoritative name servers must not appear in the name servers set in the zone database.'
  desc 'A hidden master authoritative server is an authoritative DNS server in which the IP address does not appear in the name server set for a zone. All of the name servers that do appear in the zone database as designated name servers get their zone data from the hidden master via a zone transfer request. In effect, all visible name servers are actually secondary slave servers. This prevents potential attackers from targeting the master name server because its IP address may not appear in the zone database.'
  desc 'check', 'Verify that the Infoblox Grid Master is not configured to service DNS requests from clients.

1. Navigate to Data Management >> DNS >> Zones. 
2. Review each zone by selecting the zone, clicking "Edit", and selecting the "Name Servers" tab.  

If the Grid Master is a listed name server and not marked "Stealth", this is a finding.'
  desc 'fix', 'For each zone that is not in compliance:  

1. Navigate to Data Management >> DNS >> Zones.  
2. Reconfigure the "Name Servers" tab and modify the Grid Master by selecting "Stealth". 
3. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
4. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37061r611148_chk'
  tag severity: 'medium'
  tag gid: 'V-233876'
  tag rid: 'SV-233876r621666_rule'
  tag stig_id: 'IDNS-8X-400018'
  tag gtitle: 'SRG-APP-000516-DNS-000108'
  tag fix_id: 'F-37026r611149_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
