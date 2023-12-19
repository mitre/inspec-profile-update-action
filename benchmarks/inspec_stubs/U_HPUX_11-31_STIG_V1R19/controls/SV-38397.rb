control 'SV-38397' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the mode of the LDAP key file(s).
# ls -lLa /etc/opt/ldapux/key3.db

If the permissions of the file contains a "+", an extended ACL is present and this is a finding.)
  desc 'fix', 'Remove the extended ACL from the key file.   
# chacl -z <key file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36784r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22574'
  tag rid: 'SV-38397r1_rule'
  tag stig_id: 'GEN008360'
  tag gtitle: 'GEN008360'
  tag fix_id: 'F-32164r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
