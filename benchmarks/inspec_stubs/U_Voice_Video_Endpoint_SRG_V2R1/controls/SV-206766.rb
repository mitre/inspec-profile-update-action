control 'SV-206766' do
  title 'When using PKI-based authentication, the Voice Video Endpoint must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure. The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to authenticate to network devices. 

This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Verify the Voice Video Endpoint, when using PKI-based authentication, enforces authorized access only to the corresponding private key. 

If the Voice Video Endpoint, when using PKI-based authentication, does not enforce authorized access to the corresponding private key, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint, when using PKI-based authentication, to enforce authorized access to the corresponding private key.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7022r363821_chk'
  tag severity: 'high'
  tag gid: 'V-206766'
  tag rid: 'SV-206766r604140_rule'
  tag stig_id: 'SRG-NET-000165-VVEP-00034'
  tag gtitle: 'SRG-NET-000165'
  tag fix_id: 'F-7022r363822_fix'
  tag 'documentable'
  tag legacy: ['SV-81241', 'V-66751']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
