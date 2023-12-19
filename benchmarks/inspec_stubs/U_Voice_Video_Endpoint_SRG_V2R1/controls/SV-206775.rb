control 'SV-206775' do
  title 'The Voice Video Endpoint processing classified information over public networks must implement NSA-approved cryptography.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the Voice Video Endpoint processing classified information over public networks implements NSA-approved cryptography. 

If the Voice Video Endpoint processing classified information over public networks does not implement NSA-approved cryptography, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint processing classified information over public networks to implement NSA-approved cryptography.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7031r363848_chk'
  tag severity: 'high'
  tag gid: 'V-206775'
  tag rid: 'SV-206775r604140_rule'
  tag stig_id: 'SRG-NET-000352-VVEP-00038'
  tag gtitle: 'SRG-NET-000352'
  tag fix_id: 'F-7031r363849_fix'
  tag 'documentable'
  tag legacy: ['SV-81249', 'V-66759']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
