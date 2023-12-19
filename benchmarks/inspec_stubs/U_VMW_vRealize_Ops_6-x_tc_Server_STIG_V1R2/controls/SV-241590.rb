control 'SV-241590' do
  title 'tc Server API must use cryptography to protect the integrity of remote sessions.'
  desc "Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

HTTP connections in tc Server are managed through the Connector object. Setting the Connector's “SSLEnabled” flag, SSL handshake/encryption/decryption is enabled."
  desc 'check', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to the <Connector> node that contains 'port="${vmware-ssl.https.port}"'.

If the value of “SSLEnabled” is not set to “true” or is missing, this is a finding.)
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to the <Connector> node that contains 'port="${vmware-ssl.https.port}"'.

Configure each <Connector> with the value 'SSLEnabled="true"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44866r683630_chk'
  tag severity: 'medium'
  tag gid: 'V-241590'
  tag rid: 'SV-241590r879520_rule'
  tag stig_id: 'VROM-TC-000090'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-44825r683631_fix'
  tag 'documentable'
  tag legacy: ['SV-99459', 'V-88809']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
