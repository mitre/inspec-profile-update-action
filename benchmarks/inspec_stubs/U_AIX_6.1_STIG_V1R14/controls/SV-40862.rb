control 'SV-40862' do
  title 'The SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is not a DoD-approved protocol and has many well-known vulnerability exploits.  Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', 'Examine the sshd configuration file.

# cat /etc/ssh/sshd_config | grep -i "Protocol 2" 

If the value of "Protocol" is not set to 2, or is commented out, this is a finding.'
  desc 'fix', 'Edit the configuration file and modify the Protocol line.

Protocol 2

Restart sshd:

/sbin/init.d/secsh stop
/sbin/init.d/secsh start'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39554r3_chk'
  tag severity: 'high'
  tag gid: 'V-4295'
  tag rid: 'SV-40862r2_rule'
  tag stig_id: 'GEN005500'
  tag gtitle: 'GEN005500'
  tag fix_id: 'F-4206r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
