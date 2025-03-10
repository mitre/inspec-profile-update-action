control 'SRG-NET-000400-VVEP-00033_rule' do
  title 'The Unified Communications Endpoint, when using passwords or PINs for authentication or authorization, must be configured to cryptographically protect the PIN or password.'
  desc 'Passwords need to be protected at all times and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Verify the Unified Communications Endpoint, when using passwords or PINs for authentication or authorization, cryptographically protects the transmission. 

If the Unified Communications Endpoint, when using passwords or PINs for authentication or authorization, does not cryptographically protect the transmission, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint, when using passwords or PINs for authentication or authorization, to cryptographically protect the transmission.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000400-VVEP-00033_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000400-VVEP-00033'
  tag rid: 'SRG-NET-000400-VVEP-00033_rule'
  tag stig_id: 'SRG-NET-000400-VVEP-00033'
  tag gtitle: 'SRG-NET-000400-VVEP-00033'
  tag fix_id: 'F-SRG-NET-000400-VVEP-00033_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
