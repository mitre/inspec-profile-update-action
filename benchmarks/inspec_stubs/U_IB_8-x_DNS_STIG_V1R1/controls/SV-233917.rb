control 'SV-233917' do
  title 'Infoblox DNS servers must protect the authenticity of communications sessions for zone transfers when communicating with external DNS servers.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. 

Communication sessions between different DNS systems should employ protections such as DNSSEC or TSIG to validate the integrity of data being transmitted.'
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab. 
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab.  
3. If all name server entries in the "Type" column are configured as "Grid", this check is Not Applicable. 
4. Verify that each zone containing non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE). 
5. When complete, click "Cancel" to exit the "Properties" screen.  

If there is a non-Grid system that uses zone transfers but does not have a TSIG key, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones tab.  Select a zone and click "Edit". 
2. Click on the "Zone Transfers" tab and click "Override" for the "Allow Zone Transfers to" section. 
3. Use the radio button to select "Set of ACEs" and the "Add" drop-down to configure a TSIG key. 
4. It is important to verify that both the Infoblox and other DNS server have the identical TSIG configuration and time synchronization. 
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.
6. Perform a service restart if necessary. 7. Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37102r611271_chk'
  tag severity: 'medium'
  tag gid: 'V-233917'
  tag rid: 'SV-233917r621666_rule'
  tag stig_id: 'IDNS-8X-700012'
  tag gtitle: 'SRG-APP-000219-DNS-000028'
  tag fix_id: 'F-37067r611272_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
