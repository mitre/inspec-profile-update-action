control 'SV-218700' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be owned by root.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if LDAP is used for account information on the system.

To check to see if the system is an LDAP server, verify LDAP is running on the system:

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

Check whether the server option has an address other than the loopback, then check the nsswitch.conf file.

# grep ldap /etc/nsswitch.conf

Look for the following three lines:

passwd: files ldap
shadow: files ldap
group: files ldap

If no uncommented reference to "ldap" is identified, LDAP is not used for account information on the system and this is not applicable.

Determine the certificate authority file and/or directory.
# grep -i '^tls_cacert' /etc/ldap.conf

For each file or directory returned, check the ownership.
# ls -lLd <certpath>

If the owner of any file or directory is not root, this is a finding.)
  desc 'fix', 'Change the ownership of the file or directory.

# chown root <certpath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20175r556517_chk'
  tag severity: 'medium'
  tag gid: 'V-218700'
  tag rid: 'SV-218700r603259_rule'
  tag stig_id: 'GEN008140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20173r556518_fix'
  tag 'documentable'
  tag legacy: ['V-22563', 'SV-63303']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
