control 'SV-38392' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the mode of the LDAP cert file(s).
# ls -lLa /etc/opt/ldapux/cert8.db

If the certificate file is more permissive than 0644, this is a finding.)
  desc 'fix', 'Change the permissions of the LDAP client certificate file.
# chmod 0644 <cert file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36778r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22569'
  tag rid: 'SV-38392r1_rule'
  tag stig_id: 'GEN008260'
  tag gtitle: 'GEN008260'
  tag fix_id: 'F-32159r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
