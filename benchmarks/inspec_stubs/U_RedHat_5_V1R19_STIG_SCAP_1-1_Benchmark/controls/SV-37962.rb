control 'SV-37962' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must have mode 0644 (0755 for directories) or less permissive.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the mode of the file or directory.

File Procedure:
# chmod 0644 <certpath> 

Directory Procedure:
# chmod 0755 <certpath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22565'
  tag rid: 'SV-37962r1_rule'
  tag stig_id: 'GEN008180'
  tag gtitle: 'GEN008180'
  tag fix_id: 'F-32448r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
