control 'SV-38721' do
  title 'The system must not have the rstatd service active.'
  desc 'The rstatd can give out information on the running system, such as  the CPU usage,  the system uptime, its network usage, and other system information that could potentially aid in an attack.  The rstatd service is unnecessary and it weakens the defensive posture of the system.  If systems monitoring is needed,  use a third party tool or SNMP.'
  desc 'check', 'Check the /etc/inetd.conf file for active rstatd service.

#grep rstatd /etc/inetd.conf | grep -v \\#

If the rstatd service is enabled, this is a finding.'
  desc 'fix', 'Edit the /etc/inetd.conf file and comment out the rstatd service line. 

Restart the inetd service.   

# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29517'
  tag rid: 'SV-38721r1_rule'
  tag stig_id: 'GEN009330'
  tag gtitle: 'GEN009330'
  tag fix_id: 'F-33075r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
