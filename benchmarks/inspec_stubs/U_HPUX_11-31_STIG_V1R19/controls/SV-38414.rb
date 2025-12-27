control 'SV-38414' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'The authentication of automated LDAP connections between systems must not use passwords since more secure methods are available, such as PKI and Kerberos. Additionally, the storage of unencrypted passwords on the system is not permitted.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP

OR

# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If the product is installed:
ls -lL /etc/opt/ldapux/acred /etc/opt/ldapux/pcred

The user credentials are stored in the pcred and acred files, including the password. While these credentials are not visible as plain text, the pcred and acred files are not encrypted. If either of the above unencrypted files exists, this is a finding.)
  desc 'fix', 'Consult vendor documentation for the procedures for configuring LDAP for authentication and account information. Remove any passwords from unencrypted LDAP configuration files.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36764r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24384'
  tag rid: 'SV-38414r1_rule'
  tag stig_id: 'GEN008050'
  tag gtitle: 'GEN008050'
  tag fix_id: 'F-32147r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
