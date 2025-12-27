control 'SV-219560' do
  title 'The SSH daemon must be configured to use only the SSHv2 protocol.'
  desc 'SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used.'
  desc 'check', 'To check which SSH protocol version is allowed, run the following command: 

# grep Protocol /etc/ssh/sshd_config

If configured properly, output should be 

Protocol 2

If it is not, this is a finding.'
  desc 'fix', 'Only SSH protocol version 2 connections should be permitted. The default setting in "/etc/ssh/sshd_config" is correct, and can be verified by ensuring that the following line appears: 

Protocol 2'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21285r358220_chk'
  tag severity: 'high'
  tag gid: 'V-219560'
  tag rid: 'SV-219560r793817_rule'
  tag stig_id: 'OL6-00-000227'
  tag gtitle: 'SRG-OS-000074'
  tag fix_id: 'F-21284r358221_fix'
  tag 'documentable'
  tag legacy: ['V-50573', 'SV-64779']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
