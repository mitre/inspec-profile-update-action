control 'SV-37643' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'The authentication of automated LDAP connections between systems must not use passwords since more secure methods are available, such as PKI and Kerberos. Additionally, the storage of unencrypted passwords on the system is not permitted.'
  desc 'check', 'Verify LDAP is running on the system. To check to see if the system is an LDAP server, run:
# ps -ef | grep ldap

Find out which LDAP is used (if not determined via the command above).
# rpm -qa | grep ldap

If using nssldap:
# grep base /etc/ldap.conf

Check to see if the base is set to something besides the default of "dc=example,dc=com".

If using openldap:
# grep suffix /etc/openldap/slapd.conf

Check whether the system is an LDAP client:
# grep server /etc/ldap.conf
# grep server /etc/openldap/ldap.conf

Check whether the server option has an address other than the loopback, then check the nsswitch.conf file:
# grep ldap /etc/nsswitch.conf 

Look for the following three lines:
passwd: files ldap
shadow: files ldap
group: files ldap

If all three files are not configured to look for an LDAP source, then the system is not using LDAP for authentication.

If the system is not using LDAP for authentication, this is not applicable.

Check for the "bindpw" option being used in the "/etc/ldap.conf" file.
# grep bindpw /etc/ldap.conf

If an uncommented "bindpw" option is returned, then a cleartext password is in the file, and this is a finding.'
  desc 'fix', 'Edit the "/etc/ldap.conf" file to use anonymous binding by removing the "bindpw" option.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36837r4_chk'
  tag severity: 'medium'
  tag gid: 'V-24384'
  tag rid: 'SV-37643r3_rule'
  tag stig_id: 'GEN008050'
  tag gtitle: 'GEN008050'
  tag fix_id: 'F-31678r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
