control 'SV-106391' do
  title 'The ISEC7 EMM Suite must configure Enable HTTPS to use HTTP over SSL in Apache Tomcat.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Verify Enable HTTPS has been configured to use HTTP over SSL:

Open a web browser that is able to reach the ISEC7 EMM Suite console.
Verify that the address used has a prefix of https://

Alternately:

Log in to the ISEC7 EMM Suite server.
Open the server.xml file located at <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf with Notepad.exe
Select Edit >> Find and search for Connector port="443" 
Confirm the connector is present and not commented out:

<Connector port="443" useServerCipherSuitesOrder="true" sslImplementationName="org.apache.tomcat.util.net.jsse.JSSEImplementation" secure="true" scheme="https" protocol="org.apache.coyote.http11.Http11NioProtocol" maxThreads="200" keystoreType="Windows-MY" keystoreFile="" keyAlias="https" clientAuth="none" ciphers="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_RSA_WITH_RC4_128_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,TLS_EMPTY_RENEGOTIATION_INFO_SCSVF" SSLEnabled="true"/>

If Enable HTTPS has not been configured to use HTTP over SSL, this is a finding.'
  desc 'fix', 'To enable HTTPS to use HTTP over SSL, run the ISEC7 integrated installer or use the following manual procedure:

Log in to the ISEC7 EMM Suite server.
Open the server.xml file located at <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf with Notepad.exe
Select Edit >> Find and search for Connector port="443" 
If the connector is not present add:

<Connector port="443" useServerCipherSuitesOrder="true" sslImplementationName="org.apache.tomcat.util.net.jsse.JSSEImplementation" secure="true" scheme="https" protocol="org.apache.coyote.http11.Http11NioProtocol" maxThreads="200" keystoreType="Windows-MY" keystoreFile="" keyAlias="https" clientAuth="none" ciphers="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_ECDSA_WITH_RC4_128_SHA,TLS_ECDH_RSA_WITH_RC4_128_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,TLS_EMPTY_RENEGOTIATION_INFO_SCSVF" SSLEnabled="true"/>

If the connector has been commented out, remove the comment characters.
Save the file.
Restart the ISEC7EMM Suite Web service in the services.msc'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97287'
  tag rid: 'SV-106391r1_rule'
  tag stig_id: 'ISEC-06-550800'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-102967r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
