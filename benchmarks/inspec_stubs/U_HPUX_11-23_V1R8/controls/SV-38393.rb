control 'SV-38393' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the mode of the LDAP cert file(s).
# ls -lLa /etc/opt/ldapux/cert8.db

If the permissions of the file contains a "+", an extended ACL is present, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the certificate file.   
# chacl -z <certfile>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36780r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22570'
  tag rid: 'SV-38393r1_rule'
  tag stig_id: 'GEN008280'
  tag gtitle: 'GEN008280'
  tag fix_id: 'F-32160r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
