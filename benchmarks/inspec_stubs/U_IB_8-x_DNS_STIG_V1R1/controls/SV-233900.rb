control 'SV-233900' do
  title 'The Infoblox DNS server must authenticate to any external (non-Grid) DNS servers before responding to a server-to-server transaction.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific preauthorized devices can access the system. 

This requirement applies to server-to-server (zone transfer) transactions only and is provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG).'
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab.  
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab.  
3. If the all entries in the "Type" column are configured as "Grid", this check is Not Applicable.  
4. Verify that each zone containing non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE). 
5. When complete, click "Cancel" to exit the "Properties" screen. 

If there is a non-Grid system that uses zone transfers but does not have a TSIG key, this is a finding.'
  desc 'fix', 'Note that TSIG relies on both key and time synchronization. TSIG will fail if the local clocks on both names are not synchronized. 

1. Navigate to the Data Management >> DNS >> Zones tab. 
2. Select a zone and click "Edit". Click on the "Zone Transfers" tab and click "Override" for the "Allow Zone Transfers to" section.  
3. Use the radio button to select "Set of ACEs" and the "Add" drop-down to configure a TSIG key.  
4. It is important to verify that both the Infoblox and other DNS server have the identical TSIG configuration.  
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
6. Perform a service restart if necessary.
7. Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37085r611220_chk'
  tag severity: 'medium'
  tag gid: 'V-233900'
  tag rid: 'SV-233900r621666_rule'
  tag stig_id: 'IDNS-8X-500003'
  tag gtitle: 'SRG-APP-000394-DNS-000049'
  tag fix_id: 'F-37050r611221_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
