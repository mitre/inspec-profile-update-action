control 'SV-45759' do
  title 'The xinetd.conf files must have mode 0640 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the mode of the xinetd configuration files.

Procedure:
# ls -lL /etc/xinetd.conf 
# ls -lL /etc/xinetd.d
If the mode of the file(s) is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the xinetd configuration files.
# chmod 0640 /etc/xinetd.conf /etc/xinetd.d/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43113r1_chk'
  tag severity: 'medium'
  tag gid: 'V-822'
  tag rid: 'SV-45759r2_rule'
  tag stig_id: 'GEN003740'
  tag gtitle: 'GEN003740'
  tag fix_id: 'F-39159r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
