control 'SV-240864' do
  title 'tc Server VCAC must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

As a Tomcat derivative, tc Server uses a port (defaults to 8005) as a shutdown port. If enabled, a shutdown signal can be sent to tc Server through this port. To ensure availability, the shutdown port should be disabled.'
  desc 'check', 'At the command prompt, execute the following command:

grep base.shutdown.port /etc/vcac/catalina.properties

If the value of "base.shutdown.port" is not set to "-1" or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vcac/catalina.properties.

Navigate to the "base.shutdown.port" setting.

Add the setting "base.shutdown.port=-1" to the "catalina.properties" file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44097r674334_chk'
  tag severity: 'medium'
  tag gid: 'V-240864'
  tag rid: 'SV-240864r879806_rule'
  tag stig_id: 'VRAU-TC-000850'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-44056r674335_fix'
  tag 'documentable'
  tag legacy: ['SV-100807', 'V-90157']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
