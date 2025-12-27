control 'SV-218501' do
  title 'The xinetd configuration files must have mode 0640 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the mode of the xinetd configuration files.

Procedure:
# ls -lL /etc/xinetd.conf 
# ls -lL /etc/xinetd.d
If the mode of the file(s) is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the xinetd configuration files.
# chmod 0640 /etc/xinetd.conf /etc/xinetd.d/*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19976r562636_chk'
  tag severity: 'medium'
  tag gid: 'V-218501'
  tag rid: 'SV-218501r603259_rule'
  tag stig_id: 'GEN003740'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19974r562637_fix'
  tag 'documentable'
  tag legacy: ['V-822', 'SV-64239']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
