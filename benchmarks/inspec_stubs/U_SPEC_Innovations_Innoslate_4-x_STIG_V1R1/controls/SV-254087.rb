control 'SV-254087' do
  title 'Innoslate must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to Transport Layer Security (TLS) gateways (also known as Secure Sockets Layer [SSL] gateways), web servers, and web applications and is not applicable to virtual private network (VPN) devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance for client negotiation on either DoD-only or on public-facing servers.

'
  desc 'check', '1. Consult the System Administrator if needed to determine the location of the Apache Tomcat server.xml file and the network port that was specified during installation for use with Innoslate. The default is 8443; other AO-approved ports may be used.
2. Open the server.xml file with a text editor, and locate the <Connector/> element.  The following is an example:

Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="false" SSLProtocol="TLSv1.2" 
               keystoreFile="$keystorepath"
               keystorePass="123456"
               keyAlias="tomcatssl"
               /

If "port" is not set to 8443, or other AO-approved port, this is a finding.
If "protocol" is not set to "org.apache.coyote.http11.Http11NioProtocol", this is a finding.
If "SSLEnabled" is not set to "true", this is a finding.
If "scheme" is not set to "https", this is a finding.
If "secure" is not set to "true", this is a finding.
If "SSLProtocol"or "SSLEnabledProtocols" is not set to "TLSv1.2", this is a finding. The name of this flag varies with Tomcat versions.'
  desc 'fix', '1. Open the server.xml file inside the conf folder of the tomcat installation (IE "C:\\Innoslate4\\apache-tomcat\\conf" or "$CATALINA_BASE/conf/server.xml"). Add a connector tag for HTTPS scheme with PORT 8443 (or other AO-approved port) using the following example:

Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="false" sslProtocol="TLSv1.2" 
               keystoreFile="C:\\Innoslate4\\apache-tomcat-8.5.30\\conf\\keystore.jks"
               keystorePass="123456"
               keyAlias="tomcatssl"
               /

2. Set "port" to 8443, or other AO-approved port.
Set "protocol" to "org.apache.coyote.http11.Http11NioProtocol".
Set "SSLEnabled" to "true".
Set "scheme" to "https".
Set "secure" to "true".
Set "SSLProtocol" or "SSLEnabledProtocols" to "TLSv1.2".  The name of this flag varies with Tomcat versions.
Set "keystoreFile" to the path of the keystore utilized by the system, and set the associated password with "keystorePass".

3. Save the server.xml file.'
  impact 0.7
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57572r845235_chk'
  tag severity: 'high'
  tag gid: 'V-254087'
  tag rid: 'SV-254087r845265_rule'
  tag stig_id: 'SPEC-IN-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-57523r845236_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000156', 'SRG-APP-000179', 'SRG-APP-000442', 'SRG-APP-000555', 'SRG-APP-000560', 'SRG-APP-000565', 'SRG-APP-000605', 'SRG-APP-000635', 'SRG-APP-000645', 'SRG-APP-000219']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000185', 'CCI-000382', 'CCI-000803', 'CCI-001184', 'CCI-001453', 'CCI-001941', 'CCI-002422', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'IA-5 (2) (b) (1)', 'CM-7 b', 'IA-7', 'SC-23', 'AC-17 (2)', 'IA-2 (8)', 'SC-8 (2)', 'SC-13 b']
end
