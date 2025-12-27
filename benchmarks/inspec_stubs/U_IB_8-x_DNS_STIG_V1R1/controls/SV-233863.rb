control 'SV-233863' do
  title 'The Infoblox DNS server must be configured so that each name server (NS) record in a zone file points to an active name server authoritative for the domain specified in that record.'
  desc "Poorly constructed NS records pose a security risk because they create conditions under which an adversary might be able to provide the missing authoritative name services that are improperly specified in the zone file. The adversary could issue bogus responses to queries that clients would accept because they learned of the adversary's name server from a valid authoritative name server, one that need not be compromised for this attack to be successful.

The list of slave servers must remain current within 72 hours of any changes to the zone architecture that would affect the list of slaves. If a slave server has been retired or is not operational but remains on the list, an adversary might have a greater opportunity to impersonate that slave without detection, rather than if the slave were actually online. For example, the adversary may be able to spoof the retired slave's IP address without an IP address conflict, which would not be likely to occur if the true slave were active."
  desc 'check', 'Verify that NS resource records in all active zones point to an operational name server.

1. Navigate to Data Management >> DNS >> Zones 
2. Select the zone to review.  
3. Select the "Name Servers" tab.  
4. If the option "Use this Name Server Group" is active, note the group name used. Click "Cancel" and select the "Name Server Groups" tab to review the name server group.  
5. Examine each NS record and name server configuration.
6. Verify that the IP address for each NS record points to an operational name server.
7. Click "Cancel" to exit the "Properties" screen.

If a name server resource record points to an IP that is not an operational name server, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones. 
2. Select and edit the zones containing incorrect NS record configurations.  
3. Select the "Name Servers" tab.  
4. If the option "Use this Name Server Group" is active, note the group name used. Click "Cancel" and select the "Name Server Groups" tab to edit the name server group.  
5. Remove or update any incorrect NS records or name server configuration. 
6. If the option "Use this set of name servers" is active, remove or update any incorrect NS records or name server configuration. 
7. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
8. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37048r611109_chk'
  tag severity: 'medium'
  tag gid: 'V-233863'
  tag rid: 'SV-233863r621666_rule'
  tag stig_id: 'IDNS-8X-400005'
  tag gtitle: 'SRG-APP-000516-DNS-000085'
  tag fix_id: 'F-37013r611110_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
