control 'SV-41996' do
  title 'If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires protection.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is Not A Finding. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | \
grep -v "^#" | grep -i ldap

If LDAP is installed, verify that TLS is enabled.
# cat /etc/opt/ldapux/ldapux_client.conf | tr '\011' ' ' | tr -s ' ' | \
sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i "^enable_startTLS = 1"

If TLS is not enabled, this is a finding.

Verify the certificate database exists.
# ls -alL /etc/opt/ldapux/cert*

List the LDAP Directory Server certificate.
# /opt/ldapux/contrib/bin/certutil -L -d /etc/opt/ldapux 

List the details when checking the Directory Server's certificate validity/attributes. Note: The format of the validity-time argument when specifying an explicit time is "YYMMDDHHMMSSZ". Specifying seconds (SS) is optional. 
# /opt/ldapux/contrib/bin/certutil -V -n <Directory Server nickname> -b <validity-time> [-e] -l -d /etc/opt/ldapux 
If the Directory Server's certificate cannot be verified, this is a finding.

NOTE: The TLS protocol supports a variety of cryptographic ciphers for authenticating the server and client to each other, transmitting certificates and establishing session keys. When the LDAP-UX client connects to the LDAP Directory Server, the server selects the strongest cipher supported by both client and server. As LDAP-UX is the client side of the LDAP application, LDAP-UX has no control over this process. 

Unless it can be determined that the Directory Server is using FIPS 140-2 approved cryptographic algorithms for the TLS connection, this check will result in an OPEN Finding.)
  desc 'fix', 'The Directory Server must support and be configured to use FIPS 140-2 approved cryptographic algorithms for the TLS connection.

For the LDAPUX client:
# vi /etc/opt/ldapux/ldapux_client.conf

If commented, uncomment the "enable_startTLS" keyword line and ensure that the keyword value is set to 1 (to start TLS), IE:

enable_startTLS = 1

Finally, use the following commands to reread the configuration file and restart ldapclientd.:
# /opt/ldapux/bin/ldapclientd -k
# nohup /opt/ldapux/bin/ldapclientd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-40430r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22555'
  tag rid: 'SV-41996r1_rule'
  tag stig_id: 'GEN007980'
  tag gtitle: 'GEN007980'
  tag fix_id: 'F-35635r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
