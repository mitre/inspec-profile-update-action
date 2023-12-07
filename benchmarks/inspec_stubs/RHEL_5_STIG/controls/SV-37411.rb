control 'SV-37411' do
  title 'The xinetd.d directory must not have an extended ACL.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22426'
  tag rid: 'SV-37411r1_rule'
  tag stig_id: 'GEN003755'
  tag gtitle: 'GEN003755'
  tag fix_id: 'F-31341r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
