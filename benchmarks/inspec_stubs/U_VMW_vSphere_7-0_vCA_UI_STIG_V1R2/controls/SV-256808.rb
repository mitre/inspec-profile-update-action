control 'SV-256808' do
  title 'vSphere UI must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration. If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to vSphere UI through this port. To ensure availability, the shutdown port must be disabled.'
  desc 'check', %q(At the command prompt, run the following commands: 
 
# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2 s/xmlns=".*"//g' |  xmllint --xpath '/Server/@port' - 
 
Expected result: 
 
port="${shutdown.port}" 
 
If the output does not match the expected result, this is a finding. 
 
# grep shutdown /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json|sed -e 's/^[ ]*//' 
 
Expected result: 
 
"-Dshutdown.port=-1", 
 
If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open: 
 
/usr/lib/vmware-vsphere-ui/server/conf/server.xml 
 
Ensure the server port is disabled: 
 
<Server port="${shutdown.port}"> 
 
Restart the service with the following command: 
 
# vmon-cli --restart vsphere-ui'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA UI'
  tag check_id: 'C-60483r889421_chk'
  tag severity: 'medium'
  tag gid: 'V-256808'
  tag rid: 'SV-256808r889423_rule'
  tag stig_id: 'VCUI-70-000031'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-60426r889422_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
