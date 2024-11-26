control 'SV-822' do
  title 'The inetd.conf and xinetd.conf files must have mode 0440 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'fix', 'Change the mode of the inetd.conf file.
# chmod 0440 /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-822'
  tag rid: 'SV-822r2_rule'
  tag stig_id: 'GEN003740'
  tag gtitle: 'GEN003740'
  tag fix_id: 'F-976r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
