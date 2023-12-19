control 'SV-214197' do
  title 'The DNS server implementation must maintain the integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Confidentiality is not an objective of DNS, but integrity is. DNS is responsible for maintaining the integrity of DNS information while it is being prepared for transmission.'
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
  tag check_id: 'C-15412r295854_chk'
  tag severity: 'medium'
  tag gid: 'V-214197'
  tag rid: 'SV-214197r612370_rule'
  tag stig_id: 'IDNS-7X-000610'
  tag gtitle: 'SRG-APP-000441-DNS-000066'
  tag fix_id: 'F-15410r295855_fix'
  tag 'documentable'
  tag legacy: ['SV-83079', 'V-68589']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
