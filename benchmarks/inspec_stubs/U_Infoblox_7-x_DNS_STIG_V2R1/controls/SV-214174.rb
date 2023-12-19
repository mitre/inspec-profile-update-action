control 'SV-214174' do
  title 'Infoblox DNS servers must protect the authenticity of communications sessions for zone transfers.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. 

If communication sessions are not provided appropriate validity protections, such as the employment of DNSSEC, the authenticity of the data cannot be guaranteed.'
  desc 'check', 'Navigate to Data Management >> DNS >> Zones tab.

Review each zone by clicking "Edit" and inspecting the "Name Servers" tab. 

If the all entries in the "Type" column are configured as "Grid", this check is not applicable.

Verify that each zone which contains non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE).

If there is a non-Grid system which utilizes zone transfers but does not have a TSIG key, this is a finding.

When complete, click "Cancel" to exit the "Properties" screen.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Zones tab.

Select a zone and click "Edit". 
Click on "Zone Transfers" tab, and click "Override" for the "Allow Zone Transfers to" section. 
Use the radio button to select "Set of ACEs" and the "Add" dropdown to configure a TSIG key. It is important to verify that both the Infoblox and other DNS server have the identical TSIG configuration. 
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.

Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15389r295785_chk'
  tag severity: 'medium'
  tag gid: 'V-214174'
  tag rid: 'SV-214174r612370_rule'
  tag stig_id: 'IDNS-7X-000270'
  tag gtitle: 'SRG-APP-000219-DNS-000028'
  tag fix_id: 'F-15387r295786_fix'
  tag 'documentable'
  tag legacy: ['V-68545', 'SV-83035']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
