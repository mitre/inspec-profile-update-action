control 'SV-38396' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must have mode 0600 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. The LDAP client configuration must be protected from unauthorized modification.

NOTE: Depending on the particular implementation, group and other read permission may be necessary for unprivileged users to successfully resolve account information using LDAP. This will still be a finding, as these permissions provide users with access to system authenticators.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the mode of the key file.
# ls -lLa /etc/opt/ldapux/key3.db

If the file permission is more permissive than 0600, this is a finding.)
  desc 'fix', 'Change the mode of the file.
# chmod 0600 <key file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22573'
  tag rid: 'SV-38396r1_rule'
  tag stig_id: 'GEN008340'
  tag gtitle: 'GEN008340'
  tag fix_id: 'F-32163r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
