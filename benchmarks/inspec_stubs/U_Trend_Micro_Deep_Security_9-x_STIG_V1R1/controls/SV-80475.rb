control 'SV-80475' do
  title 'Trend Deep Security must only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure only the use of DoD PKI established certificate authorities are allowed for verification of the establishment of protected sessions.

Verify the certificate CA and by reviewing the issued to and validity date by clicking the certificate icon in the web browser and selecting View Certificates, Certificate Information, etc. (browser dependent). 

If the certificate is not issued by a DoD CA, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.

1. Run the following command to create a CSR for your CA to sign:
C:\\Program Files\\Trend Micro\\Deep Security Manager\\jre\\bin>keytool -certreq -keyalg RSA -alias tomcat -file certrequest.csr
2. Send the certrequest.csr to your CA to sign. In return you will get two files. One is a "certificate reply" and the second is the CA certificate itself.
3. Run the following command to import the CA cert in JAVA trusted keystore:
C:\\Program Files\\Trend Micro\\Deep Security Manager\\jre\\bin>keytool -import -alias root -trustcacerts -file cacert.crt -keystore "C:\\Program Files\\Trend Micro\\Deep Security Manager\\jre\\lib\\security\\cacerts"
4. Run the following command to import the CA certificate in your keystore:
C:\\Program Files\\Trend Micro\\Deep Security Manager\\jre\\bin>keytool -import -alias root -trustcacerts -file cacert.crt (say yes to warning message)
5. Run the following command to import the certificate reply to your keystore:
C:\\Program Files\\Trend Micro\\Deep Security Manager\\jre\\bin>keytool -import -alias tomcat -file certreply.txt
6. Run the following command to view the certificate chain in you keystore:
C:\\Program Files\\Trend Micro\\Deep Security Manager\\jre\\bin>keytool -list -v
7. Copy the .keystore file from your user home directory C:\\Documents and Settings\\Administrator to C:\\Program Files\\ Trend Micro \\Deep Security Manager\\
8. Open the configuration.properties file in folder C:\\Program Files\\Trend Micro\\Deep Security Manager. It will look something like:
keystore File=C\\:\\\\\\\\Program Files\\\\\\\\Trend Micro\\\\\\\\Deep Security Manager\\\\\\\\.keystore
port=4119
keystorePass=$1$85ef650a5c40bb0f914993ac1ad855f48216fd0664ed2544bbec6de80160b2f
installed=true
serviceName= Trend Micro Deep Security Manager
9. Replace the password in the following string:
keystorePass=xxxx
where "xxxx" is the password you supplied in step five
10. Save and close the file
11. Restart the Deep Security Manager service
12. Connect to the Deep Security Manager with your browser and you will notice that the new SSL certificate is signed by your CA.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65985'
  tag rid: 'SV-80475r1_rule'
  tag stig_id: 'TMDS-00-000305'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-72061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
