control 'SV-218691' do
  title 'If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires protection.'
  desc 'check', %q(To check to see if the system is an LDAP server, verify LDAP is running on the system:

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

If all three files are not configured to look for an LDAP source, then the system is not using LDAP for authentication.

If the system is not using LDAP for authentication, this is not applicable.

Check if NSS LDAP is using TLS.

# grep '^ssl start_tls' /etc/ldap.conf

If no lines are returned, this is a finding.

Check if NSS LDAP TLS is using only FIPS 140-2 approved cryptographic algorithms.

# grep '^tls_ciphers' /etc/ldap.conf

If the line is not present or contains ciphers not approved by FIPS 140-2, this is a finding.

FIPS-approved ciphers include 3DES and AES. FIPS-approved hashes include the SHA hash family.)
  desc 'fix', 'Edit "/etc/ldap.conf" and add a "ssl start_tls" and "tls_ciphers" options with only FIPS 140-2 approved ciphers.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20166r556490_chk'
  tag severity: 'medium'
  tag gid: 'V-218691'
  tag rid: 'SV-218691r603259_rule'
  tag stig_id: 'GEN007980'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-20164r556491_fix'
  tag 'documentable'
  tag legacy: ['V-22555', 'SV-63369']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
