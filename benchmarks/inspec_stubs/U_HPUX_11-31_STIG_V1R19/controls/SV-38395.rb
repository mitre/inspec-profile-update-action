control 'SV-38395' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be group-owned by root, bin, sys, or other.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the group ownership of the key file.
# ls -lLa /etc/opt/ldapux/key3.db

If the file is not group owned by root, bin, sys, or other, this is a finding.)
  desc 'fix', 'Change the group owner of the LDAP client key file.
# chgrp root <key file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36782r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22572'
  tag rid: 'SV-38395r1_rule'
  tag stig_id: 'GEN008320'
  tag gtitle: 'GEN008320'
  tag fix_id: 'F-32162r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
