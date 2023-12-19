control 'SV-207627' do
  title 'The ESXi host SSH daemon must set a timeout count on idle sessions.'
  desc 'This ensures a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config

If there is no output or the output is not exactly "ClientAliveCountMax 3", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveCountMax 3'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7882r364280_chk'
  tag severity: 'low'
  tag gid: 'V-207627'
  tag rid: 'SV-207627r388482_rule'
  tag stig_id: 'ESXI-65-000026'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7882r364281_fix'
  tag 'documentable'
  tag legacy: ['SV-104085', 'V-93999']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
