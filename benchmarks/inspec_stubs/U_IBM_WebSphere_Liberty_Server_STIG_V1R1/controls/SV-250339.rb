control 'SV-250339' do
  title 'The WebSphere Liberty Server must use FIPS 140-2 approved encryption modules when authenticating users and processes.'
  desc 'Application servers must use and meet requirements of the DoD Enterprise PKI infrastructure for application authentication. Encryption is only as good as the encryption modules used. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. The use of TLS provides confidentiality of data in transit between the application server and client. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. 

TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.

'
  desc 'check', 'Review the ${server.config.dir}/jvm.options file. Verify FIPS is in use. If the -Dcom.ibm.jsse2.usefipsprovider=true property is not set in the ${server.config.dir}/jvm.options file, this is a finding.

Review the ${JAVA_HOME}/jre/lib/security/java.security file. If the ${JAVA_HOME}/jre/lib/security/java.security file does not contain the following settings, this is a finding. 

ssl.SocketFactory.provider=com.ibm.jsse2.SSLSocketFactoryImpl
ssl.ServerSocketFactory.provider=com.ibm.jsse2.SSLServerSocketFactoryImpl

Locate the list of cryptographic providers and replace it with the following list in the following order:

security.provider.1=com.ibm.crypto.fips.provider.IBMJCEFIPS
security.provider.2=com.ibm.jsse2.IBMJSSEProvider2
security.provider.3=com.ibm.crypto.provider.IBMJCE
security.provider.4=com.ibm.security.jgss.IBMJGSSProvider
security.provider.5=com.ibm.security.cert.IBMCertPath
security.provider.6=com.ibm.security.sasl.IBMSASL
security.provider.7=com.ibm.xml.crypto.IBMXMLCryptoProvider
security.provider.8=com.ibm.xml.enc.IBMXMLEncProvider
security.provider.9=org.apache.harmony.security.provider.PolicyProvider
security.provider.10=com.ibm.security.jgss.mech.spnego.IBMSPNEGO'
  desc 'fix', 'Edit the ${server.config.dir}/jvm.options file. Add or modify the -Dcom.ibm.jsse2.usefipsprovider=true property to enable the JSSE2 provider to run in FIPS 140-2 mode. 

Edit ${JAVA_HOME}/jre/lib/security/java.security file to register additional cryptographic package provides. Update these two lines: 

#ssl.SocketFactory.provider=
#ssl.ServerSocketFactory.provider=
to
ssl.SocketFactory.provider=com.ibm.jsse2.SSLSocketFactoryImpl
ssl.ServerSocketFactory.provider=com.ibm.jsse2.SSLServerSocketFactoryImpl

Locate the list of cryptographic providers that are located after the line
# List
of providers and their preference orders and replace it with the following list:
security.provider.1=com.ibm.crypto.fips.provider.IBMJCEFIPS
security.provider.2=com.ibm.jsse2.IBMJSSEProvider2
security.provider.3=com.ibm.crypto.provider.IBMJCE
security.provider.4=com.ibm.security.jgss.IBMJGSSProvider
security.provider.5=com.ibm.security.cert.IBMCertPath
security.provider.6=com.ibm.security.sasl.IBMSASL
security.provider.7=com.ibm.xml.crypto.IBMXMLCryptoProvider
security.provider.8=com.ibm.xml.enc.IBMXMLEncProvider
security.provider.9=org.apache.harmony.security.provider.PolicyProvider
security.provider.10=com.ibm.security.jgss.mech.spnego.IBMSPNEGO'
  impact 0.7
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53774r795068_chk'
  tag severity: 'high'
  tag gid: 'V-250339'
  tag rid: 'SV-250339r795070_rule'
  tag stig_id: 'IBMW-LS-000520'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-53728r795069_fix'
  tag satisfies: ['SRG-APP-000179-AS-000129', 'SRG-APP-000224-AS-000152', 'SRG-APP-000416-AS-000140', 'SRG-APP-000439-AS-000155', 'SRG-APP-000442-AS-000259', 'SRG-APP-000514-AS-000136']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002418', 'CCI-002422', 'CCI-002450']
  tag nist: ['IA-7', 'SC-23 (3)', 'SC-8', 'SC-8 (2)', 'SC-13 b']
end
