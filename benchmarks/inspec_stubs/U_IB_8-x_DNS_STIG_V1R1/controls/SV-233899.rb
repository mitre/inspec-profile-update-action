control 'SV-233899' do
  title 'When using non-Grid DNS servers for zone transfers, each name server must use TSIG to uniquely identify the other server.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. This applies to server-to-server (zone transfer) transactions only and is provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG), thus uniquely identifying the other server.'
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab. 
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab. 
3. Verify that each zone that contains non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE). 
4. When complete, click "Cancel" to exit the "Properties" screen.  

If all entries in the "Type" column are configured as "Grid", this check is Not Applicable.

If there is a non-Grid system that uses zone transfers but does not have a TSIG key, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones tab.  
2. Select a zone and click "Edit".
3. Click on the "Zone Transfers" tab and click "Override" for the "Allow Zone Transfers to" section.
4. Use the radio button to select "Set of ACEs" and the "Add" drop-down to configure a TSIG key. 
5. Verify that both the Infoblox and other DNS server have the identical TSIG configuration. 
6. Verify that both the Infoblox and other DNS server have time synchronized properly. Note that TSIG relies on both key and time synchronization. TSIG will fail if the local clocks on both names are not synchronized.
7. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.
8. Perform a service restart if necessary.
9. Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37084r611217_chk'
  tag severity: 'medium'
  tag gid: 'V-233899'
  tag rid: 'SV-233899r621666_rule'
  tag stig_id: 'IDNS-8X-500002'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-37049r611218_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
