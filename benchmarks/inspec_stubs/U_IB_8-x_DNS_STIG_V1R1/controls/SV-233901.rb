control 'SV-233901' do
  title 'The Infoblox DNS server must authenticate another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

This requirement applies to server-to-server (zone transfer) transactions only and is provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG).'
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab.  
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab.  
3. If all entries in the "Type" column are configured as "Grid", this check is Not Applicable.  
4. Verify that each zone containing non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE). 
5. When complete, click "Cancel" to exit the "Properties" screen. 

If there is a non-Grid system that uses zone transfers but does not have a TSIG key, this is a finding.'
  desc 'fix', 'It is important to verify that both the Infoblox and other DNS server have the identical TSIG configuration and time synchronization before starting this procedure. 

1. Navigate to the Data Management >> DNS >> Zones tab.  
2. Select a zone and click "Edit". Click on the "Zone Transfers" tab and click "Override" for the "Allow Zone Transfers to" section.  
3. Use the radio button to select "Set of ACEs" and the "Add" drop-down to configure a TSIG key.  
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
5. Perform a service restart if necessary. Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37086r611223_chk'
  tag severity: 'medium'
  tag gid: 'V-233901'
  tag rid: 'SV-233901r621666_rule'
  tag stig_id: 'IDNS-8X-500004'
  tag gtitle: 'SRG-APP-000395-DNS-000050'
  tag fix_id: 'F-37051r611224_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
