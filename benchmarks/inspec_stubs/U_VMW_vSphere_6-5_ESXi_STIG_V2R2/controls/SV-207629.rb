control 'SV-207629' do
  title 'The ESXi host SSH daemon must limit connections to a single session.'
  desc 'The SSH protocol has the ability to provide multiple sessions over a single connection without reauthentication. A compromised client could use this feature to establish additional sessions to a system without consent or knowledge of the user.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^MaxSessions" /etc/ssh/sshd_config

If there is no output or the output is not exactly "MaxSessions 1", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

MaxSessions 1'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7884r364286_chk'
  tag severity: 'medium'
  tag gid: 'V-207629'
  tag rid: 'SV-207629r388482_rule'
  tag stig_id: 'ESXI-65-000028'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7884r364287_fix'
  tag 'documentable'
  tag legacy: ['V-94003', 'SV-104089']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
