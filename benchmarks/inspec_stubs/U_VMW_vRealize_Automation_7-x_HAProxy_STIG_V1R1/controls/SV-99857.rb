control 'SV-99857' do
  title 'HAProxy must be protected from being stopped by a non-privileged user.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

To prohibit an attacker from stopping the HAProxy process must be owned by "root".'
  desc 'check', "At the command prompt, execute the following command:

ps aux -U root | grep '[h]aproxy'

If the command does not return a line, this is a finding."
  desc 'fix', 'Restart the HAProxy service as "root".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89207'
  tag rid: 'SV-99857r1_rule'
  tag stig_id: 'VRAU-HA-000425'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-95949r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
