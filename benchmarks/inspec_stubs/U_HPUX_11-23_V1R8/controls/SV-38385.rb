control 'SV-38385' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be group-owned by root, bin, sys, or other.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

Check the group ownership of the LDAP configuration file(s).
ls -lL /etc/opt/ldapux/ldapux_client.conf /etc/opt/ldapux/ldapclientd.conf /etc/opt/ldapux/ldapug.conf

If any of the above files are not group owned by root, bin, sys, or other, this is a finding.)
  desc 'fix', 'Change the group owner of the file to root, bin, sys, or other.
# chgrp root <LDAP configuration file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36768r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22561'
  tag rid: 'SV-38385r1_rule'
  tag stig_id: 'GEN008100'
  tag gtitle: 'GEN008100'
  tag fix_id: 'F-32150r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
