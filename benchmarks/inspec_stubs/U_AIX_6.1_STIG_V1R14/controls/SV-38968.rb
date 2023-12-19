control 'SV-38968' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'The authentication of automated LDAP connections between systems must not use passwords since more secure methods are available, such as PKI and Kerberos. Additionally, the storage of unencrypted passwords on the system is not permitted.'
  desc 'check', %q(Examine the LDAP configuration file(s). 

#grep bindpwd: /etc/security/ldap/ldap.cfg
If the returned entry has an unencrypted password (not like "bindpwd:{DES}"), this is a finding.  
If the LDAP configuration file contains an encrypted password accessible by regular users on the system, this is a finding.
#ls -l /etc/security/ldap/ldap.cfg

Check for unencrypted SSL keyfile password.
#grep '^ldapsslkeypwd' /etc/security/ldap/ldap.cfg
If the returned entry has an unencrypted password (not like "ldapsslkeypwd:{DES}"), this is a finding.)
  desc 'fix', 'Remove any passwords from LDAP configuration files.  

The bindpw (bind password) can  be encrypted with the mksecldap command.  
#mksecldap

Stash the SSL key database file with the gsk7cmd or ikeyman commands.
#gsk7cmd < or > ikeyman

Comment out the ldapsslpwd line to use stashed password. The password stash file must reside in the same directory as the SSL key database, and must have the same name as the key database, but with an extension of .sth instead of .kdb.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24384'
  tag rid: 'SV-38968r1_rule'
  tag stig_id: 'GEN008050'
  tag gtitle: 'GEN008050'
  tag fix_id: 'F-33177r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
