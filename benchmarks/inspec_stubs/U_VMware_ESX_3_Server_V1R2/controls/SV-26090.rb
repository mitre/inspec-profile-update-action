control 'SV-26090' do
  title 'The xinetd.d directory must not have an extended ACL.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial-of-Service or increase the attack surface of the system.'
  desc 'check', 'Check xinetd configuration directories for extended ACLs.

Determine any xinetd configuration directories.
Procedure:
# grep includedir /etc/xinetd.conf

If xinetd.conf does not exist, or no includedir lines are returned, this is not applicable.

Check the xinetd configuration directories for extended ACLs.
Procedure:
# ls -lL <directory>

If any of these directories contain a "+" in the permissions field, the directory has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the xinetd configuration directories.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30072r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22426'
  tag rid: 'SV-26090r1_rule'
  tag stig_id: 'GEN003755'
  tag gtitle: 'GEN003755'
  tag fix_id: 'F-26901r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
