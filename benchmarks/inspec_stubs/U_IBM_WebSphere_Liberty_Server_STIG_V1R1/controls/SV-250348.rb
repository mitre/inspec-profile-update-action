control 'SV-250348' do
  title 'The WebSphere Liberty Server must be configured to use HTTPS only.'
  desc 'Transmission of data can take place between the application server and a large number of devices/applications external to the application server. Examples are a web client used by a user, a backend database, a log server, or other application servers in an application server cluster.'
  desc 'check', 'Review the ${server.config.dir}/server.xml file and check the ssl-1.0 feature and httpEndpoint settings. 

If the ssl-1.0 feature is not defined, this is a finding. 

If the httpEndpoint settings do not include ssloptions, this is a finding.

<featureManager>
    <feature>timedexit-1.0</feature>
        <feature>servlet-3.0</feature>
        <feature>ssl-1.0</feature>
        <feature>appSecurity-2.0</feature>
    </featureManager>

<httpEndpoint id="defaultHttpEndpoint"
          host="localhost"
          httpPort="${bvt.prop.HTTP_default}"
          httpsPort="${bvt.prop.HTTP_default.secure}" >
          <tcpOptions soReuseAddr="true" />
          <sslOptions sslRef="testSSLConfig" />
</httpEndpoint>'
  desc 'fix', 'Modify the server.xml file. Enable the ssl-1.0 feature and configure the httpEndpoint settings. The keystores and truststores must also be configured.

<featureManager>
    <feature>timedexit-1.0</feature>
        <feature>servlet-3.0</feature>
        <feature>ssl-1.0</feature>
        <feature>appSecurity-2.0</feature>
    </featureManager>
    
    <httpEndpoint id="defaultHttpEndpoint"
          host="localhost"
          httpPort="${bvt.prop.HTTP_default}"
          httpsPort="${bvt.prop.HTTP_default.secure}" >
          <tcpOptions soReuseAddr="true" />
          <sslOptions sslRef="testSSLConfig" />
</httpEndpoint> 

     <ssl id="defaultSSLConfig"
      keyStoreRef="defaultKeyStore"
      trustStoreRef="defaultKeyStore"
      serverKeyAlias="default" />

     <ssl id="testSSLConfig"
      keyStoreRef="defaultKeyStore"
      trustStoreRef="alternateTrustStore"
      serverKeyAlias="alternateCert"
      enabledCiphers="AES256-SHA AES128-SHA" />

<!-- inbound (HTTPS) keystore -->
<keyStore id="defaultKeyStore" password="Liberty"
           location="${server.config.dir}/resources/security/sslOptions.jks" />

<keyStore id="defaultTrustStore" password="Liberty"
           location="${server.config.dir}/resources/security/trust.jks" />
           
<keyStore id="alternateTrustStore" password="Liberty"
           location="${server.config.dir}/resources/security/optionsTrust.jks" />

    <application type="war" id="basicauth" name="basicauth"
             location="${server.config.dir}/apps/basicauth.war" />'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53783r795095_chk'
  tag severity: 'medium'
  tag gid: 'V-250348'
  tag rid: 'SV-250348r795097_rule'
  tag stig_id: 'IBMW-LS-001120'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-53737r795096_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
