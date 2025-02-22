control 'SV-221458' do
  title 'A private OHS list of CAs in a trust hierarchy must lead to an authorized DoD PKI Root CA.'
  desc 'A PKI certificate is a digital identifier that establishes the identity of an individual or a platform. A server that has a certificate provides users with third-party confirmation of authenticity. Most web browsers perform server authentication automatically; the user is notified only if the authentication fails. The authentication process between the server and the client is performed using the SSL/TLS protocol. Digital certificates are authenticated, issued, and managed by a trusted Certification Authority (CA). 

The use of a trusted certificate validation hierarchy is crucial to the ability to control access to the server and prevent unauthorized access. This hierarchy needs to lead to the DoD PKI Root CA or to an approved External Certificate Authority (ECA) or are required for the server to function.'
  desc 'check', '1. Go to the location of the OHS keystores (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores).

2. For each wallet directory located there, do the following:

a) Issue the command "$ORACLE_HOME/oracle_common/bin/orapki wallet display -wallet <wallet_directory>".
b) Confirm that only the appropriate DoD Certificate Authorities are listed as Trusted Certificates and that the Identity Certificate has been issued by a DoD Certificate authority.

3. If any of the Trusted Certificates are not appropriate DoD Certificate Authorities or the Identity Certificate has not been issued by a DoD Certificate authority, this is a finding.'
  desc 'fix', '1. Go to the location of the OHS keystores (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores).

2. For each wallet directory located there, do the following:

a) Issue the command "$ORACLE_HOME/oracle_common/bin/orapki wallet display -wallet <wallet_directory>".
b) Remove the Identity Certificate if it was not issued by a DoD Certificate authority.
c) Remove each Trusted Certificate from the wallet that is not an appropriate DoD Certificate Authority with the command "$ORACLE_HOME/oracle_common/bin/orapki wallet remove -wallet <wallet_directory> -dn <dn_of_the_trusted_certificate> -trusted_cert".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23173r415057_chk'
  tag severity: 'medium'
  tag gid: 'V-221458'
  tag rid: 'SV-221458r879887_rule'
  tag stig_id: 'OH12-1X-000221'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23162r415058_fix'
  tag 'documentable'
  tag legacy: ['SV-79169', 'V-64679']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
