control 'SV-207617' do
  title 'The ESXi host SSH daemon must not permit user environment settings.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations. Users must not be able to present environment options to the SSH daemon.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitUserEnvironment no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

PermitUserEnvironment no'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7872r364250_chk'
  tag severity: 'medium'
  tag gid: 'V-207617'
  tag rid: 'SV-207617r388482_rule'
  tag stig_id: 'ESXI-65-000016'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7872r364251_fix'
  tag 'documentable'
  tag legacy: ['V-93979', 'SV-104065']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
