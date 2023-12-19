control 'SV-206784' do
  title 'The Voice Video Endpoint processing unclassified information must implement NIST FIPS-validated cryptography to provision digital signatures.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the Voice Video Endpoint processing unclassified information implements NIST FIPS-validated cryptography to provision digital signatures.

If the Voice Video Endpoint processing unclassified information does not implement NIST FIPS-validated cryptography to provision digital signatures, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint processing unclassified information to implement NIST FIPS-validated cryptography to provision digital signatures.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7040r363875_chk'
  tag severity: 'high'
  tag gid: 'V-206784'
  tag rid: 'SV-206784r604140_rule'
  tag stig_id: 'SRG-NET-000510-VVEP-00040'
  tag gtitle: 'SRG-NET-000510'
  tag fix_id: 'F-7040r363876_fix'
  tag 'documentable'
  tag legacy: ['V-66803', 'SV-81293']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
