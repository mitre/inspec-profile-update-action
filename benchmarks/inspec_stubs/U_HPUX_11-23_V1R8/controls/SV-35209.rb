control 'SV-35209' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=Protocol
Required arg(s)=2

Default arg values include: "2,1"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> are not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "Protocol" | cut -f 2,2 -d " "

If the return value is "1" or "2,1" (double quotes are for emphasis only) , this is a finding.)
  desc 'fix', 'Edit the configuration file and modify the Protocol line entry  to appear as follows:

Protocol 2'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35053r1_chk'
  tag severity: 'high'
  tag gid: 'V-4295'
  tag rid: 'SV-35209r1_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'GEN005500'
  tag fix_id: 'F-30340r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1, DCPP-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
