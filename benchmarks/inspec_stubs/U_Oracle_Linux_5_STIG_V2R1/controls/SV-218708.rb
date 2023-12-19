control 'SV-218708' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the key file.

# grep -i '^tls_key' /etc/ldap.conf

Check the ownership.
# ls -lL <keypath>

If the owner of the file is not root, this is a finding."
  desc 'fix', 'Change the ownership of the file.
# chown root <keypath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20183r556541_chk'
  tag severity: 'medium'
  tag gid: 'V-218708'
  tag rid: 'SV-218708r603259_rule'
  tag stig_id: 'GEN008300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20181r556542_fix'
  tag 'documentable'
  tag legacy: ['V-22571', 'SV-63243']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
