control 'SV-77713' do
  title 'The SSH daemon must set a timeout interval on idle sessions.'
  desc 'Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.'
  desc 'check', 'To verify the ClientAliveInterval setting, run the following command: 

# grep -i "^ClientAliveInterval" /etc/ssh/sshd_config

If there is no output or the output is not exactly "ClientAliveInterval 200", this is a finding.'
  desc 'fix', 'To set the ClientAliveInterval setting, add or correct the following line in "/etc/ssh/sshd_config":

ClientAliveInterval 200'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63957r1_chk'
  tag severity: 'low'
  tag gid: 'V-63223'
  tag rid: 'SV-77713r1_rule'
  tag stig_id: 'ESXI-06-000027'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
