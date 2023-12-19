control 'SV-227975' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must have mode 0644 (0755 for directories) or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify the mode of the certificate database files.
# ls -lL /var/ldap/cert8.db /var/ldap/key3.db /var/ldap/secmod.db
If the mode of any of the files is more permissive than 0644, this is a finding."
  desc 'fix', 'Change the mode of the certificate database files.
# chmod 0644 /var/ldap/cert8.db /var/ldap/key3.db /var/ldap/secmod.db

NOTE:  Some SAs may prefer to set the permissions to 0600.  This is acceptable.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30137r490360_chk'
  tag severity: 'medium'
  tag gid: 'V-227975'
  tag rid: 'SV-227975r603266_rule'
  tag stig_id: 'GEN008180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30125r490361_fix'
  tag 'documentable'
  tag legacy: ['V-22565', 'SV-40760']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
