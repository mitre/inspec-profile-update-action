control 'SV-218503' do
  title 'The xinetd.d directory must have mode 0755 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the xinetd configuration directories.
# ls -dlL /etc/xinetd.d
If the mode of the directory is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the directory.
# chmod 0755 /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19978r562642_chk'
  tag severity: 'medium'
  tag gid: 'V-218503'
  tag rid: 'SV-218503r603259_rule'
  tag stig_id: 'GEN003750'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19976r562643_fix'
  tag 'documentable'
  tag legacy: ['V-22425', 'SV-64243']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
