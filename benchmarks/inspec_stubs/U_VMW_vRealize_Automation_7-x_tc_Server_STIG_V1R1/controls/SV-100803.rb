control 'SV-100803' do
  title 'tc Server HORIZON must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

As a Tomcat derivative, tc Server uses a port (defaults to 8005) as a shutdown port. If enabled, a shutdown signal can be sent to tc Server through this port. To ensure availability, the shutdown port should be disabled.'
  desc 'check', 'At the command prompt, execute the following command:

grep base.shutdown.port /opt/vmware/horizon/workspace/conf/catalina.properties

If the value of "base.shutdown.port" is not set to "-1" or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/catalina.properties.

Navigate to the "base.shutdown.port" setting.

Add the setting "base.shutdown.port=-1" to the "catalina.properties" file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90153'
  tag rid: 'SV-100803r1_rule'
  tag stig_id: 'VRAU-TC-000840'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-96895r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
