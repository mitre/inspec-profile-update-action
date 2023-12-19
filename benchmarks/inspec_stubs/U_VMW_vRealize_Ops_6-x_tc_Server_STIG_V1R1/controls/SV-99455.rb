control 'SV-99455' do
  title 'tc Server UI must use cryptography to protect the integrity of remote sessions.'
  desc "Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

HTTP connections in tc Server are managed through the Connector object. Setting the Connector's “SSLEnabled” flag, SSL handshake/encryption/decryption is enabled."
  desc 'check', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of “SSLEnabled” is not set to “true” or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> with the value 'SSLEnabled="true"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88497r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88805'
  tag rid: 'SV-99455r1_rule'
  tag stig_id: 'VROM-TC-000080'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-95547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
