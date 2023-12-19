control 'SV-256698' do
  title 'ESX Agent Manager must hide the server version.'
  desc 'Web servers will often display error messages to client users, including enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, the Security Token Service must be configured with a catch-all error handler that redirects to a standard "error.jsp".'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector/@server' /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

server="Anonymous"

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Configure the <Connector> node with the value:

server="Anonymous"

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA EAM'
  tag check_id: 'C-60373r888648_chk'
  tag severity: 'medium'
  tag gid: 'V-256698'
  tag rid: 'SV-256698r888650_rule'
  tag stig_id: 'VCEM-70-000026'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-60316r888649_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
