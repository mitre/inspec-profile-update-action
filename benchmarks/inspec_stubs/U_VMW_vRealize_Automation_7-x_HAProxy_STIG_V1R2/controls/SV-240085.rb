control 'SV-240085' do
  title 'HAProxy must be protected from being stopped by a non-privileged user.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

To prohibit an attacker from stopping the HAProxy process must be owned by "root".'
  desc 'check', "At the command prompt, execute the following command:

ps aux -U root | grep '[h]aproxy'

If the command does not return a line, this is a finding."
  desc 'fix', 'Restart the HAProxy service as "root".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43318r665422_chk'
  tag severity: 'medium'
  tag gid: 'V-240085'
  tag rid: 'SV-240085r879806_rule'
  tag stig_id: 'VRAU-HA-000425'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-43277r665423_fix'
  tag 'documentable'
  tag legacy: ['SV-99857', 'V-89207']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
