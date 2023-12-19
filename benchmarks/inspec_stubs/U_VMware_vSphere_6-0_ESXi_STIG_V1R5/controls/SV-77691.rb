control 'SV-77691' do
  title 'The SSH daemon must not permit user environment settings.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations.'
  desc 'check', 'To verify users are not able to present environment daemons, run the following command: 

# grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config

If there is no output or the output is not exactly "PermitUserEnvironment no", this is a finding.'
  desc 'fix', 'To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in "/etc/ssh/sshd_config": 

PermitUserEnvironment no'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63201'
  tag rid: 'SV-77691r1_rule'
  tag stig_id: 'ESXI-06-000016'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
