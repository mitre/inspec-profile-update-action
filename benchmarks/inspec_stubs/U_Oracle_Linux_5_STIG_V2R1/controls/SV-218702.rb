control 'SV-218702' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must have mode 0644 (0755 for directories) or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate authority file and/or directory.

Procedure:
# grep -i '^tls_cacert' /etc/ldap.conf
For each file or directory returned, check the permissions.

Procedure:
# ls -lLd <certpath>

If the mode of the file is more permissive than 0644 (or 0755 for directories), this is a finding."
  desc 'fix', 'Change the mode of the file or directory.

File Procedure:
# chmod 0644 <certpath> 

Directory Procedure:
# chmod 0755 <certpath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20177r556523_chk'
  tag severity: 'medium'
  tag gid: 'V-218702'
  tag rid: 'SV-218702r603259_rule'
  tag stig_id: 'GEN008180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20175r556524_fix'
  tag 'documentable'
  tag legacy: ['V-22565', 'SV-63289']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
