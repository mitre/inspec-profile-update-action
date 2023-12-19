control 'SV-38969' do
  title 'If the system is using LDAP for authentication or account information the /etc/ldap.conf (or equivalent) file must have mode 0644 or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the permissions of the /etc/security/ldap/ldap.cfg file.
# ls -lL /etc/security/ldap/ldap.cfg

If the mode of the file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions of the /etc/security/ldap/ldap.cfg file to 0644 or less permissive.

# chmod 0644 /etc/security/ldap/ldap.cfg'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37922r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22559'
  tag rid: 'SV-38969r1_rule'
  tag stig_id: 'GEN008060'
  tag gtitle: 'GEN008060'
  tag fix_id: 'F-33178r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
