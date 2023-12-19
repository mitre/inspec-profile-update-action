control 'SV-239275' do
  title 'The ESXi host SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^StrictModes" /etc/ssh/sshd_config

If there is no output or the output is not exactly "StrictModes yes", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

StrictModes yes'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42508r674752_chk'
  tag severity: 'medium'
  tag gid: 'V-239275'
  tag rid: 'SV-239275r674754_rule'
  tag stig_id: 'ESXI-67-000020'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42467r674753_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
