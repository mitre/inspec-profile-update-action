control 'SV-223001' do
  title 'Application servers must use NIST-approved or NSA-approved key management technology and processes.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc 'check', 'For the systemd Ubuntu OS, check the tomcat.service file to read the content of the JAVA_OPTS environment variable setting.

sudo cat /etc/systemd/system/tomcat.service |grep -i truststore

EXAMPLE output:
set JAVA_OPTS="-Djavax.net.ssl.trustStore=/path/to/truststore" "-Djavax.net.ssl.trustStorePassword=************"

If the variable is not set, use the default location command below. If the variable is set, use the alternate location command below and include the path and truststore file. 

-Default location:
keytool -list -cacerts -v | grep -i issuer

-Alternate location:
keytool -list -keystore <location of trust store file> -v |grep -i issuer

If there are no CA certificates issued by a Certificate Authority (CA) that is part of the DoD PKI/PKE, this is a finding.'
  desc 'fix', 'Obtain and install the DoD PKI CA certificate bundles by accessing the DoD PKI office website at cyber.mil/pki-pke.

Import the DoD CA certificates.'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24673r426447_chk'
  tag severity: 'low'
  tag gid: 'V-223001'
  tag rid: 'SV-223001r879885_rule'
  tag stig_id: 'TCAT-AS-001640'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-24662r426448_fix'
  tag 'documentable'
  tag legacy: ['SV-111525', 'V-102585']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
