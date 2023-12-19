control 'SV-77715' do
  title 'The SSH daemon must limit connections to a single session.'
  desc 'The SSH protocol has the ability to provide multiple sessions over a single connection without reauthentication. A compromised client could use this feature to establish additional sessions to a system without consent or knowledge of the user.'
  desc 'check', 'To verify the MaxSessions setting, run the following command: 

# grep -i "^MaxSessions" /etc/ssh/sshd_config

If there is no output or the output is not exactly "MaxSessions 1", this is a finding.'
  desc 'fix', 'To set the MaxSessions setting, add or correct the following line in "/etc/ssh/sshd_config":

MaxSessions 1'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63959r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63225'
  tag rid: 'SV-77715r1_rule'
  tag stig_id: 'ESXI-06-000028'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69143r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
