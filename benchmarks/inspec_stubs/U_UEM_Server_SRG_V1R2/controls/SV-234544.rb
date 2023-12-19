control 'SV-234544' do
  title 'The UEM server, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', 'Verify the UEM server, for PKI-based authentication, implements a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

If the UEM server, for PKI-based authentication, does not implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network, this is a finding.'
  desc 'fix', 'Configure the UEM server to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37729r851619_chk'
  tag severity: 'medium'
  tag gid: 'V-234544'
  tag rid: 'SV-234544r879774_rule'
  tag stig_id: 'SRG-APP-000401-UEM-000272'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-37694r615276_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
