control 'SV-208922' do
  title 'The SSH daemon must set a timeout count on idle sessions.'
  desc 'This ensures a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc 'check', 'To ensure the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command: 

# grep ClientAliveCountMax /etc/ssh/sshd_config

If properly configured, output should be: 

ClientAliveCountMax 0

If it is not, this is a finding.'
  desc 'fix', 'To ensure the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, edit "/etc/ssh/sshd_config" as follows: 

ClientAliveCountMax 0'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9175r357746_chk'
  tag severity: 'low'
  tag gid: 'V-208922'
  tag rid: 'SV-208922r793708_rule'
  tag stig_id: 'OL6-00-000231'
  tag gtitle: 'SRG-OS-000126'
  tag fix_id: 'F-9175r357747_fix'
  tag 'documentable'
  tag legacy: ['V-50577', 'SV-64783']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
