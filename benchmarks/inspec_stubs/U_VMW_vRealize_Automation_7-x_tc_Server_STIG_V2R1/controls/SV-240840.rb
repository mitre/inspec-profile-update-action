control 'SV-240840' do
  title 'tc Server VCO must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 

tc Server provides a session timeout parameter in the web.xml configuration file.'
  desc 'check', 'At the command prompt, execute the following command:

grep session-timeout /etc/vco/app-server/web.xml

If the value of <session-timeout> is not "30" or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vco/app-server/web.xml.

Navigate to the <session-config> node.

Add the <session-timeout>30</session-timeout> node setting to the <session-config> node.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44073r674262_chk'
  tag severity: 'medium'
  tag gid: 'V-240840'
  tag rid: 'SV-240840r674264_rule'
  tag stig_id: 'VRAU-TC-000700'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-44032r674263_fix'
  tag 'documentable'
  tag legacy: ['SV-100761', 'V-90111']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
