control 'SV-217994' do
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19475r376997_chk'
  tag severity: 'high'
  tag gid: 'V-217994'
  tag rid: 'SV-217994r603264_rule'
  tag stig_id: 'RHEL-06-000227'
  tag gtitle: 'SRG-OS-000112'
  tag fix_id: 'F-19473r376998_fix'
  tag 'documentable'
  tag legacy: ['V-38607', 'SV-50408']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
