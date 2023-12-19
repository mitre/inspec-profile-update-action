control 'SV-37409' do
  title 'The inetd.conf and xinetd.conf files must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/xinetd.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22424'
  tag rid: 'SV-37409r1_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'GEN003745'
  tag fix_id: 'F-31339r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
