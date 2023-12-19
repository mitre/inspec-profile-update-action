control 'SV-239680' do
  title 'The Security Token Service must disable the shutdown port.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a denial of service, and the second is to put in place changes the attacker made to the web server configuration. If the Tomcat shutdown port feature is enabled, a shutdown signal can be sent to the Security Token Service through this port. To ensure availability, the shutdown port must be disabled.'
  desc 'check', "At the command prompt, execute the following command:

# grep 'base.shutdown.port' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Expected result:

base.shutdown.port=-1

If the output of the command does not match the expected result, this is a finding."
  desc 'fix', 'Open /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties in a text editor.

Add or modify the following setting:

base.shutdown.port=-1'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42913r679110_chk'
  tag severity: 'medium'
  tag gid: 'V-239680'
  tag rid: 'SV-239680r679112_rule'
  tag stig_id: 'VCST-67-000029'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-42872r679111_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
