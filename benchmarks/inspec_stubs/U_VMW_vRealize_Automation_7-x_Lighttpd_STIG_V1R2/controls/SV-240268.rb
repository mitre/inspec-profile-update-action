control 'SV-240268' do
  title 'Lighttpd must be protected from being stopped by a non-privileged user.'
  desc 'An attacker has at least two reasons to stop a web server. The first is to cause a DoS, and the second is to put in place changes the attacker made to the web server configuration. 

To prohibit an attacker from stopping the Lighttpd, the process ID (pid) must be owned by privileged users.'
  desc 'check', %q(At the command prompt, execute the following command:

ps -f -U root | awk '$0 ~ /vami-lighttpd/ && $0 !~ /awk/ {print}'

If the "vami-lighttpd" process is not owned by "root", this is a finding.)
  desc 'fix', 'Note:  The following command must be ran as root.

At the command prompt, execute the following command:

/opt/vmware/etc/init.d/vami-lighttpd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43501r667979_chk'
  tag severity: 'medium'
  tag gid: 'V-240268'
  tag rid: 'SV-240268r879806_rule'
  tag stig_id: 'VRAU-LI-000450'
  tag gtitle: 'SRG-APP-000435-WSR-000147'
  tag fix_id: 'F-43460r667980_fix'
  tag 'documentable'
  tag legacy: ['SV-99961', 'V-89311']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
