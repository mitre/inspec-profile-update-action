control 'SV-220121' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate authority file and/or directory (as appropriate) must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify the permissions of the certificate database files.
# ls -lL /var/ldap/cert8.db /var/ldap/key3.db /var/ldap/secmod.db
If the permissions of any of the files contain a "+", and extended ACL is present, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the certificate database files.
# chmod A- /var/ldap/cert8.db /var/ldap/key3.db /var/ldap/secmod.db'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21830r490363_chk'
  tag severity: 'medium'
  tag gid: 'V-220121'
  tag rid: 'SV-220121r603266_rule'
  tag stig_id: 'GEN008200'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21829r490364_fix'
  tag 'documentable'
  tag legacy: ['V-22566', 'SV-37427']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
