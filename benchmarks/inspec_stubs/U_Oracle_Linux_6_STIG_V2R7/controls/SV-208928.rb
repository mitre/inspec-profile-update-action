control 'SV-208928' do
  title 'The SSH daemon must not permit user environment settings.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations.'
  desc 'check', 'To ensure users are not able to present environment daemons, run the following command: 

# grep PermitUserEnvironment /etc/ssh/sshd_config

If properly configured, output should be: 

PermitUserEnvironment no

If it is not, this is a finding.'
  desc 'fix', 'To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in "/etc/ssh/sshd_config": 

PermitUserEnvironment no'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9181r357764_chk'
  tag severity: 'low'
  tag gid: 'V-208928'
  tag rid: 'SV-208928r793714_rule'
  tag stig_id: 'OL6-00-000241'
  tag gtitle: 'SRG-OS-000242'
  tag fix_id: 'F-9181r357765_fix'
  tag 'documentable'
  tag legacy: ['SV-65011', 'V-50805']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
