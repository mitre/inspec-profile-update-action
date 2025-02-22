control 'SV-222994' do
  title 'Certificates in the trust store must be issued/signed by an approved CA.'
  desc 'Use of self-signed certificates creates a lack of integrity and invalidates the certificate based authentication trust model. Certificates used by production systems must be issued/signed by a trusted Root CA and cannot be self-signed. For systems that communicate with industry partners, the DoD ECA program supports the issuance of DoD-approved certificates to industry partners. For information on the DoD ECA program, refer to the DoD PKI office. Links to their site are available on https://public.cyber.mil.'
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
  desc 'fix', 'Obtain and install the DoD PKI CA certificate bundles by accessing the DoD PKI office website at https://cyber.mil/pki-pke.

Download the certificate bundles and then use certificate management utilities such as keytool or openssl to import the DoD CA certificates into the trust store.'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24666r426426_chk'
  tag severity: 'medium'
  tag gid: 'V-222994'
  tag rid: 'SV-222994r879798_rule'
  tag stig_id: 'TCAT-AS-001430'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-24655r426427_fix'
  tag 'documentable'
  tag legacy: ['SV-111511', 'V-102571']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
