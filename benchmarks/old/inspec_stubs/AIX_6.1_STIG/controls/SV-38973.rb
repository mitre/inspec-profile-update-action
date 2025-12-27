control 'SV-38973' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the SSL Certificate database file and/or directory.

# grep -i '^ldapsslkeyf' /etc/security/ldap/ldap.cfg

For each file or directory returned, check the ownership.
# ls -lLd <certpath>

If the owner of any file or directory is not root, this is a finding."
  desc 'fix', 'Change the ownership of the SSL key database file or directory.

# chown root <certpath>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37926r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22563'
  tag rid: 'SV-38973r1_rule'
  tag stig_id: 'GEN008140'
  tag gtitle: 'GEN008140'
  tag fix_id: 'F-33182r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
