control 'SV-227968' do
  title 'If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires protection.

'
  desc 'check', %q(Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify TLS is used for client authentications to the server
# grep "NS_LDAP_AUTH=" /var/ldap/ldap_client_file
If any of the authentication methods used do not begin with "tls:", this is a finding.

Retrieve the list of LDAP servers.
# grep "NS_LDAP_SERVERS=" /var/ldap/client_file
Use the certutil to verify the cipher(s) used for every server.
# certutil -L -n < host nickname > -d /var/ldap
If any of the TLS connections do not use FIPS 140-2 approved cryptographic algorithms, this is a finding.)
  desc 'fix', 'Configure all LDAP authentications and connections to be encrypted using TLS and FIPS 140-2 approved cryptographic algorithms.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30130r490339_chk'
  tag severity: 'medium'
  tag gid: 'V-227968'
  tag rid: 'SV-227968r603266_rule'
  tag stig_id: 'GEN007980'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-30118r490340_fix'
  tag satisfies: ['SRG-OS-000250', 'SRG-OS-000495', 'SRG-OS-000500']
  tag 'documentable'
  tag legacy: ['V-22555', 'SV-41038']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
