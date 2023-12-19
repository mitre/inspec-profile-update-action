control 'SV-214164' do
  title 'Infoblox systems which are configured to perform zone transfers to non-Grid name servers must utilize transaction signatures (TSIG).'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. This applies to server-to-server (zone transfer) transactions only and is provided by TSIG, which enforces mutual server authentication using a key that is unique to each server pair (TSIG), thus uniquely identifying the other server.'
  desc 'check', 'Navigate to Data Management >> DNS >> Zones tab.

Review each zone by clicking Edit and inspecting the "Name Servers" tab. 

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
  tag check_id: 'C-15379r295758_chk'
  tag severity: 'medium'
  tag gid: 'V-214164'
  tag rid: 'SV-214164r612370_rule'
  tag stig_id: 'IDNS-7X-000140'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-15377r295759_fix'
  tag 'documentable'
  tag legacy: ['V-68699', 'SV-83189']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
