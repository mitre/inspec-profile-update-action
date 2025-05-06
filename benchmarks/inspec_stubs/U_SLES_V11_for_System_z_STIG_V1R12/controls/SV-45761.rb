control 'SV-45761' do
  title 'The xinetd.d directory must have mode 0755 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the xinetd configuration directories.
# ls -dlL /etc/xinetd.d
If the mode of the directory is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the directory.
# chmod 0755 /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43115r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22425'
  tag rid: 'SV-45761r1_rule'
  tag stig_id: 'GEN003750'
  tag gtitle: 'GEN003750'
  tag fix_id: 'F-39161r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
