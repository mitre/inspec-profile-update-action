control 'SV-239281' do
  title 'The ESXi host SSH daemon must set a timeout count on idle sessions.'
  desc 'Setting a timeout ensures that a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config

If there is no output or the output is not exactly "ClientAliveCountMax 3", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveCountMax 3'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42514r674770_chk'
  tag severity: 'low'
  tag gid: 'V-239281'
  tag rid: 'SV-239281r674772_rule'
  tag stig_id: 'ESXI-67-000026'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42473r674771_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
