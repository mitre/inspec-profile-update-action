control 'SV-39885' do
  title 'The inetd.conf file must have mode 0440 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'fix', 'Change the mode of the inetd.conf file.
# chmod 0440 /etc/inet/inetd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-822'
  tag rid: 'SV-39885r1_rule'
  tag stig_id: 'GEN003740'
  tag gtitle: 'GEN003740'
  tag fix_id: 'F-34403r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
