control 'SV-79593' do
  title 'The DataPower Gateway must map the authenticated identity to the user account for PKI-based authentication.'
  desc 'Authorization for access to any network device requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.'
  desc 'check', 'Search Bar “RBM” >> RBM Settings. Check that the Authentication method list has the User certificate selected. If not, this is a finding.'
  desc 'fix', 'Search Bar “RBM” >> RBM Settings. Click User certificate in the Authentication method list.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65103'
  tag rid: 'SV-79593r1_rule'
  tag stig_id: 'WSDP-NM-000065'
  tag gtitle: 'SRG-APP-000177-NDM-000263'
  tag fix_id: 'F-71043r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
