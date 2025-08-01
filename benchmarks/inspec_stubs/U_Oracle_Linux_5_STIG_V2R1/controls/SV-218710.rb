control 'SV-218710' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must have mode 0600 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.

Note:  Depending on the particular implementation, group and other read permission may be necessary for unprivileged users to successfully resolve account information using LDAP.  This will still be a finding, as these permissions provide users with access to system authenticators.'
  desc 'check', "Determine the key file.
# grep -i '^tls_key' /etc/ldap.conf
Check the permissions.
# ls -lL <keypath>
If the mode of the file is more permissive than 0600, this is a finding."
  desc 'fix', 'Change the mode of the file.
# chmod 0600 <keypath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20185r556547_chk'
  tag severity: 'medium'
  tag gid: 'V-218710'
  tag rid: 'SV-218710r603259_rule'
  tag stig_id: 'GEN008340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20183r556548_fix'
  tag 'documentable'
  tag legacy: ['V-22573', 'SV-63233']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
