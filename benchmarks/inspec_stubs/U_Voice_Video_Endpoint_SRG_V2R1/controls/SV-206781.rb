control 'SV-206781' do
  title 'The Voice Video Endpoint, when using passwords or PINs for authentication or authorization, must cryptographically-protect the transmission.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Verify the Voice Video Endpoint, when using passwords or PINs for authentication or authorization, cryptographically protects the transmission. 

If the Voice Video Endpoint, when using passwords or PINs for authentication or authorization, does not cryptographically protect the transmission, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint, when using passwords or PINs for authentication or authorization, to cryptographically protect the transmission.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7037r363866_chk'
  tag severity: 'high'
  tag gid: 'V-206781'
  tag rid: 'SV-206781r604140_rule'
  tag stig_id: 'SRG-NET-000400-VVEP-00033'
  tag gtitle: 'SRG-NET-000400'
  tag fix_id: 'F-7037r363867_fix'
  tag 'documentable'
  tag legacy: ['SV-81239', 'V-66749']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
