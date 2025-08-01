control 'SV-207621' do
  title 'The ESXi host SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^StrictModes" /etc/ssh/sshd_config

If there is no output or the output is not exactly "StrictModes yes", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

StrictModes yes'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7876r364262_chk'
  tag severity: 'medium'
  tag gid: 'V-207621'
  tag rid: 'SV-207621r388482_rule'
  tag stig_id: 'ESXI-65-000020'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7876r364263_fix'
  tag 'documentable'
  tag legacy: ['SV-104073', 'V-93987']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
