control 'SV-99727' do
  title 'tc Server API must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration.

As a Tomcat derivative, tc Server uses a port (defaults to 8005) as a shutdown port.  If enabled, a shutdown signal can be sent to tc Server through this port. To ensure availability, the shutdown port should be disabled.'
  desc 'check', 'At the command prompt, execute the following command:

grep base.shutdown.port /usr/lib/vmware-vcops/tomcat-enterprise/conf/catalina.properties

If the value of "base.shutdown.port" is not set to "-1" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/catalina.properties.

Navigate to the "base.shutdown.port" setting.

Add the setting 'base.shutdown.port=-1' to the "catalina.properties" file.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89077'
  tag rid: 'SV-99727r1_rule'
  tag stig_id: 'VROM-TC-000895'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-95819r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
