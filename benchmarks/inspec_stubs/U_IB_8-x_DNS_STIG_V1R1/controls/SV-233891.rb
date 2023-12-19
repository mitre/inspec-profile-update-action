control 'SV-233891' do
  title "The Infoblox system must validate the binding of the other DNS servers' identity to the DNS information for a server-to-server transaction (e.g., zone transfer)."
  desc "Validation of the binding of the information prevents the modification of information between production and review. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

DNSSEC is not effective unless the digital signatures they generate are validated to ensure that the information has not been tampered with and the producer's identity is legitimate."
  desc 'check', '1. Navigate to Data Management >> DNS >> Zones tab. 
2. Review each zone by clicking "Edit" and inspecting the "Name Servers" tab. 
3. If all entries in the "Type" column are configured as "Grid", this check is Not Applicable. 
4. Verify that each zone containing non-Grid name servers is further verified by inspection of the "Zone Transfers" tab and configuration of TSIG Access Control Entry (ACE). 
5. When complete, click "Cancel" to exit the "Properties" screen. 

If there is a non-Grid system that uses zone transfers but does not have a TSIG key, this is a finding.'
  desc 'fix', 'It is important to verify that both the Infoblox and other DNS server have the identical TSIG configuration and time synchronization before starting this procedure. 

1. Navigate to Data Management >> DNS >> Zones tab.  
2. Select a zone and click "Edit". Click on "Zone Transfers" tab and click "Override" for the "Allow Zone Transfers to" section.  
3. Use the radio button to select "Set of ACEs" and the "Add" drop-down to configure a TSIG key.  
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
5. Perform a service restart if necessary. 
6. Verify zone transfers are operational after configuration of TSIG.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37076r611193_chk'
  tag severity: 'medium'
  tag gid: 'V-233891'
  tag rid: 'SV-233891r621666_rule'
  tag stig_id: 'IDNS-8X-400033'
  tag gtitle: 'SRG-APP-000349-DNS-000043'
  tag fix_id: 'F-37041r611194_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001904']
  tag nist: ['CM-6 b', 'AU-10 (2) (a)']
end
