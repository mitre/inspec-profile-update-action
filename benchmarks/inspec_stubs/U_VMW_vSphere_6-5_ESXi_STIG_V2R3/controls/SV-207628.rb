control 'SV-207628' do
  title 'The ESXi hostSSH daemon must set a timeout interval on idle sessions.'
  desc 'Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^ClientAliveInterval" /etc/ssh/sshd_config

If there is no output or the output is not exactly "ClientAliveInterval 200", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveInterval 200'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7883r364283_chk'
  tag severity: 'low'
  tag gid: 'V-207628'
  tag rid: 'SV-207628r388482_rule'
  tag stig_id: 'ESXI-65-000027'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7883r364284_fix'
  tag 'documentable'
  tag legacy: ['V-94001', 'SV-104087']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
