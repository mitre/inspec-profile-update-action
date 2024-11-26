control 'SV-241694' do
  title 'tc Server UI must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed.

tc Server provides a session timeout parameter in the web.xml configuration file.'
  desc 'check', 'At the command prompt, execute the following command:

grep session-timeout /usr/lib/vmware-vcops/tomcat-web-app/webapps/ui/WEB-INF/web.xml

If the value of <session-timeout> is not “30” or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/webapps/ui/WEB-INF/web.xml.

Navigate to the <session-config> node.

Add the <session-timeout>30</session-timeout> node setting to the <session-config> node.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44970r683942_chk'
  tag severity: 'medium'
  tag gid: 'V-241694'
  tag rid: 'SV-241694r879673_rule'
  tag stig_id: 'VROM-TC-000720'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-44929r683943_fix'
  tag 'documentable'
  tag legacy: ['SV-99673', 'V-89023']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
