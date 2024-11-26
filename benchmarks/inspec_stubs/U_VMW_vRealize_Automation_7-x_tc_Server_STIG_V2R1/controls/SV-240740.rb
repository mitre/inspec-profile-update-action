control 'SV-240740' do
  title 'tc Server VCAC must use cryptography to protect the integrity of remote sessions.'
  desc "Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

HTTP connections in tc Server are managed through the Connector object. Setting the Connector's SSLEnabled flag, SSL handshake/encryption/decryption is enabled."
  desc 'check', 'Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

If the value of "SSLEnabled" is not set to "true" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

Configure the <Connector> node with the value 'SSLEnabled="true"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43973r673962_chk'
  tag severity: 'medium'
  tag gid: 'V-240740'
  tag rid: 'SV-240740r673964_rule'
  tag stig_id: 'VRAU-TC-000080'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-43932r673963_fix'
  tag 'documentable'
  tag legacy: ['SV-100993', 'V-90343']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
