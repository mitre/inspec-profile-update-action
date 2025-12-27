control 'SV-233871' do
  title 'Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.'
  desc 'Authoritative name servers (especially primary name servers) should be configured with an allow-transfer access control sub-statement designating the list of hosts from which zone transfer requests can be accepted. These restrictions address the denial-of-service threat and potential exploits from unrestricted dissemination of information about internal resources. 

Based on the need-to-know, the only name servers that need to refresh their zone files periodically are the secondary name servers. Zone transfer from primary name servers should be restricted to secondary name servers. The zone transfer should be completely disabled in the secondary name servers. The address match list argument for the allow-transfer sub-statement should consist of IP addresses of secondary name servers and stealth secondary name servers.'
  desc 'check', 'Infoblox Grid members do not use DNS zone transfers to exchange DNS data within a single Grid. Communication between Grid members is via a distributed database over a secure Virtual Private Network (VPN). 

1. Navigate to the Data Management >> DNS >> Zones tab.  
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab.  
3. Note all external DNS servers, those NOT identified as Type "Grid" (Primary or Secondary). 
4. Click the "Zone Transfers" tab. 
5. Verify that only the external non-Grid DNS servers identified as name servers for the zone or authorized stealth servers are the only systems authorized to perform zone transfers as authorized by a "Named ACL" or "Set of ACEs". 
6. When complete, click "Cancel" to exit the "Properties" screen. 

If Access Controls Lists (ACLs) are not configured for zone transfers to external non-Grid servers, this is a finding.'
  desc 'fix', '1. Navigate to the Data Management >> DNS >> Zones tab. 
2. Select the zone and click "Edit". Select the "Zone Transfers" tab and configure access control (ACL or Access Control Entries [ACE]) on each grid member that communicates with an external secondary. 
3. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
4. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37056r611133_chk'
  tag severity: 'medium'
  tag gid: 'V-233871'
  tag rid: 'SV-233871r621666_rule'
  tag stig_id: 'IDNS-8X-400013'
  tag gtitle: 'SRG-APP-000516-DNS-000095'
  tag fix_id: 'F-37021r611134_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
