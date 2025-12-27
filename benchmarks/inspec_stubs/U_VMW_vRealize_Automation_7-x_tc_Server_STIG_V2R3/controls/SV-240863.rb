control 'SV-240863' do
  title 'tc Server VCO must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

As a Tomcat derivative, tc Server uses a port (defaults to 8005) as a shutdown port. If enabled, a shutdown signal can be sent to tc Server through this port. To ensure availability, the shutdown port should be disabled.'
  desc 'check', 'At the command prompt, execute the following command:

grep shutdown /etc/vco/app-server/server.xml

If the value of "shutdown" is not set to "-1" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vco/app-server/server.xml.

Navigate to the <Server> node.

Add the attribute 'port="-1"' to the <Server> node in the "server.xml" file.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44096r674331_chk'
  tag severity: 'medium'
  tag gid: 'V-240863'
  tag rid: 'SV-240863r879806_rule'
  tag stig_id: 'VRAU-TC-000845'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-44055r674332_fix'
  tag 'documentable'
  tag legacy: ['SV-100805', 'V-90155']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
