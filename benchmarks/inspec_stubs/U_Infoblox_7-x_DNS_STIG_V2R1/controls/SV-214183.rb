control 'SV-214183' do
  title 'The Infoblox system must be configured to validate the binding of the other DNS servers identity to the DNS information for a server-to-server transaction (e.g., zone transfer).'
  desc "Validation of the binding of the information prevents the modification of information between production and review. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

DNSSEC and TSIG/SIG(0) technologies are not effective unless the digital signatures they generate are validated to ensure that the information has not been tampered with and that the producer's identity is legitimate."
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Navigate to Data Management >> DNS >> Zones tab.

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
  tag check_id: 'C-15398r295812_chk'
  tag severity: 'medium'
  tag gid: 'V-214183'
  tag rid: 'SV-214183r612370_rule'
  tag stig_id: 'IDNS-7X-000410'
  tag gtitle: 'SRG-APP-000349-DNS-000043'
  tag fix_id: 'F-15396r295813_fix'
  tag 'documentable'
  tag legacy: ['SV-83051', 'V-68561']
  tag cci: ['CCI-000366', 'CCI-001904']
  tag nist: ['CM-6 b', 'AU-10 (2) (a)']
end
