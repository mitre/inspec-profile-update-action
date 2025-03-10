control 'SV-239282' do
  title 'The ESXi host SSH daemon must set a timeout interval on idle sessions.'
  desc 'Automatically logging out idle users guards against compromises via hijacked administrative sessions.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^ClientAliveInterval" /etc/ssh/sshd_config

If there is no output or the output is not exactly "ClientAliveInterval 200", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveInterval 200'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42515r674773_chk'
  tag severity: 'low'
  tag gid: 'V-239282'
  tag rid: 'SV-239282r674775_rule'
  tag stig_id: 'ESXI-67-000027'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42474r674774_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
