control 'SV-38388' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must have mode 0644 (0755 for directories) or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the mode of the LDAP cert file(s).
# ls -lLd /etc/opt/ldapux
# ls -lLa /etc/opt/ldapux/cert8.db

If a certificate file or directory is more permissive than 0644 (or 0755 for directories), this is a finding.)
  desc 'fix', 'Change the mode of the file and/or directory.
# chmod 0755 <directory>
# chmod 0644 <directory>/<file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36772r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22565'
  tag rid: 'SV-38388r1_rule'
  tag stig_id: 'GEN008180'
  tag gtitle: 'GEN008180'
  tag fix_id: 'F-32154r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
