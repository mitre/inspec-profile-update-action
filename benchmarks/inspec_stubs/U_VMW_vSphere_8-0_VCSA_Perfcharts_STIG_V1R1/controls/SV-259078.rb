control 'SV-259078' do
  title 'The vCenter Perfcharts service must be configured to use a specified IP address and port.'
  desc 'The server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for server to use, the server will listen on all IP addresses available.

Accessing the hosted application through an IP address normally used for nonapplication functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

Navigate to the <Connector> node and configure the port and address as follows.

port="${bio.http.port}"
address="localhost"

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Perfcharts'
  tag check_id: 'C-62818r934890_chk'
  tag severity: 'medium'
  tag gid: 'V-259078'
  tag rid: 'SV-259078r934892_rule'
  tag stig_id: 'VCPF-80-000037'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-62727r934891_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
