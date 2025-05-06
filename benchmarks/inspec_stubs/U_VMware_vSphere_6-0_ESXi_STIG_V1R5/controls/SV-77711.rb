control 'SV-77711' do
  title 'The SSH daemon must set a timeout count on idle sessions.'
  desc 'This ensures a user login will be terminated as soon as the "ClientAliveCountMax" is reached.'
  desc 'check', 'To verify the ClientAliveCountMax setting, run the following command: 

# grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config

If there is no output or the output is not exactly "ClientAliveCountMax 3", this is a finding.'
  desc 'fix', 'To set the ClientAliveCountMax setting, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveCountMax 3'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63955r1_chk'
  tag severity: 'low'
  tag gid: 'V-63221'
  tag rid: 'SV-77711r1_rule'
  tag stig_id: 'ESXI-06-000026'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
