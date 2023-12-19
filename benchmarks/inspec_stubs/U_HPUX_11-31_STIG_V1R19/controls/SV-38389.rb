control 'SV-38389' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate authority file and/or directory (as appropriate) must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP

OR

# cat /etc/nsswitch.conf | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the permissions of the LDAP cert file(s).
# ls -lLd /etc/opt/ldapux
# ls -lLa /etc/opt/ldapux/cert8.db

If the permissions of the file or directory contains a "+", an extended ACL is present, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the certificate file.   
# chacl -z <directory>
# chacl -z <directory>/<file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36774r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22566'
  tag rid: 'SV-38389r1_rule'
  tag stig_id: 'GEN008200'
  tag gtitle: 'GEN008200'
  tag fix_id: 'F-32156r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
