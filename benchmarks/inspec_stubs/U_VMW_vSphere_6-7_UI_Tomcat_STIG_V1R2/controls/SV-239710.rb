control 'SV-239710' do
  title 'vSphere UI must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration. If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to vSphere UI through this port. To ensure availability, the shutdown port must be disabled.'
  desc 'check', %q(At the command prompt, execute the following commands:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2 s/xmlns=".*"//g' |  xmllint --xpath '/Server/@port' -

Expected result:

port="${shutdown.port}"

If the output does not match the expected result, this is a finding.

# grep shutdown /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json

Expected result:

"-Dshutdown.port=-1",

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml.

Make sure that the server port is disabled:

<Server port="${shutdown.port}" …>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42943r679234_chk'
  tag severity: 'medium'
  tag gid: 'V-239710'
  tag rid: 'SV-239710r679236_rule'
  tag stig_id: 'VCUI-67-000029'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-42902r679235_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
