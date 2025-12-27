control 'SV-29790' do
  title 'The xinetd.d directory must not have an extended ACL.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause denial of service or increase the attack surface of the system.'
  desc 'check', 'Check xinetd configuration directories for extended ACLs.

Determine any xinetd configuration directories.
# find / -type f -name xinetd.conf | xargs -n1 ls -lL
# cat <PATH>/xinetd.conf | grep -v "^#" | grep includedir 

If xinetd.conf does not exist, or no includedir lines are returned, 
this is not applicable.

Check the xinetd configuration directories for extended ACLs.
# ls -lLd <included directories>

If any of these directories contain a "+" in the permissions field, 
the directory has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the xinetd configuration directories.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36528r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22426'
  tag rid: 'SV-29790r1_rule'
  tag stig_id: 'GEN003755'
  tag gtitle: 'GEN003755'
  tag fix_id: 'F-26901r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
