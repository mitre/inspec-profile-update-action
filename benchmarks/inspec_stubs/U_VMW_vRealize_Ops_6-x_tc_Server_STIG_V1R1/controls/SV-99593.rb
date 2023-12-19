control 'SV-99593' do
  title 'tc Server UI must encrypt passwords during transmission.'
  desc "Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the web server for many reasons.

Examples include data passed from a user to the web server through an HTTPS connection for authentication, the web server authenticating to a backend database for data retrieval and posting, and the web server authenticating to a clustered web server manager for an update.

HTTP connections in tc Server are managed through the Connector object.  Setting the Connector's “SSLEnabled” flag, SSL handshake/encryption/decryption is enabled."
  desc 'check', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to the <Connector> node that contains 'port="${vmware-ssl.https.port}"'

If the value of “SSLEnabled” is not set to “true” or is missing, this is a finding.)
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> with the value 'SSLEnabled="true"')
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88943'
  tag rid: 'SV-99593r1_rule'
  tag stig_id: 'VROM-TC-000445'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-95685r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
