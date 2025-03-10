control 'SV-240802' do
  title 'tc Server HORIZON must encrypt passwords during transmission.'
  desc "Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the web server for many reasons. 

Examples include data passed from a user to the web server through an HTTPS connection for authentication, the web server authenticating to a backend database for data retrieval and posting, and the web server authenticating to a clustered web server manager for an update.

HTTP connections in tc Server are managed through the Connector object. Setting the Connector's SSLEnabled flag, SSL handshake/encryption/decryption is enabled."
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of "SSLEnabled" is not set to "true" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value 'SSLEnabled="true"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44035r674148_chk'
  tag severity: 'medium'
  tag gid: 'V-240802'
  tag rid: 'SV-240802r674150_rule'
  tag stig_id: 'VRAU-TC-000435'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-43994r674149_fix'
  tag 'documentable'
  tag legacy: ['SV-100687', 'V-90037']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
