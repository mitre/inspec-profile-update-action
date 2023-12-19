control 'SV-106403' do
  title 'SSL must be enabled on Apache Tomcat.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Verify SSL is enabled on Apache Tomcat.

Verify Enable HTTPS has been configured to use HTTP over SSL:

Open a web browser that is able to reach the ISEC7 EMM Suite console.
Verify that the address used has a prefix of https://

Alternately:

Login to the ISEC7 EMM Suite server.
Open the server.xml file located at <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf with Notepad.exe
Select Edit >> Find and search for Connector port="443" 
Confirm the connector is present and not commented out.

If SSL is not enabled on Apache Tomcat, this is a finding.'
  desc 'fix', 'To configure SSL support on Tomcat, run the ISEC7 integrated installer or use the following manual procedure:

To configure SSL support on Tomcat, you need to change the connector type in <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\server.xml
 
Log in to the ISEC7 EMM Suite server.
Browse to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\
Edit the server.xml with Notepad.exe
Select Edit >> Find and search for connector port=443
Replace the existing connection with the connection below, modifying the keystoreFile path and password as needed.

<Connector port="443" useServerCipherSuitesOrder="true" secure="true" scheme="https" protocol="com.isec7.bnator.utils.common.Http11NioProtocol" maxThreads="200" keystoreType="PKCS12" keystorePass="" keystoreFile="C:\\Program Files\\ISEC7 EMM Suite_nmci\\conf\\https.pfx" keyAlias="https" clientAuth="none" ciphers="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_RSA_WITH_RC4_128_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,TLS_EMPTY_RENEGOTIATION_INFO_SCSVF" SSLEnabled="true"/>

Remark: The user should not uncomment the connector tag for port 80/8080. It is recommended to keep this for the automated ISEC7 EMM Suite Agent update from the ISEC7 EMM Suite Tomcat portal (see 2.2.3). If you decline port 80/8080, the user has to enable J2SE SSL as described in section 2.2.1 with the same keystore file for very ISEC7 EMM Suite Agent host.

Then the user can click on OK and restart the Apache Tomcat service to put the new configuration into effect.

One can find further information at https://tomcat.apache.org/tomcat-8.5-doc/ssl-howto.html

Alternatively, you can use the Windows certificate store instead of a local keystore file.

<Connector port="443" protocol="org.apache.coyote.http11.Http11NioProtocol" sslImplementationName="org.apache.tomcat.util.net.jsse.JSSEImplementation" secure="true" scheme="https" maxThreads="200" SSLEnabled="true"><SSLHostConfig honorCipherOrder="true" ciphers="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_RSA_WITH_RC4_128_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,TLS_EMPTY_RENEGOTIATION_INFO_SCSVF" certificateVerification="none"><Certificate certificateKeystoreType="Windows-MY" certificateKeystoreFile="" certificateKeyAlias="https"/></SSLHostConfig>
</Connector>

The SSL certificate needs to be imported into the My user account – Personal using mmc certificate snap-in. Make sure that the cert has a friendly name, it can be verified in mmc under cert properties. The friendly name is case sensitive.'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97299'
  tag rid: 'SV-106403r1_rule'
  tag stig_id: 'ISEC-06-551600'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-102979r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
