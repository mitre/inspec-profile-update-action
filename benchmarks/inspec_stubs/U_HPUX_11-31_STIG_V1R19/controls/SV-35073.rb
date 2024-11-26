control 'SV-35073' do
  title 'The inetd.conf and xinetd.conf files must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the inetd configuration file.
# find / -type f \\( -name inetd.conf -o -name xinetd.conf \\) | xargs -n1 ls -lL

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36526r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22424'
  tag rid: 'SV-35073r1_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'GEN003745'
  tag fix_id: 'F-31887r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
