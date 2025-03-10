control 'SV-71083' do
  title 'The operating system must require devices to re-authenticate when changing authenticators.'
  desc 'Without re-authentication, devices may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to change device authenticators, it is critical the device re-authenticate.'
  desc 'check', 'Verify the operating system requires devices to re-authenticate when changing authenticators. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require devices to re-authenticate when changing authenticators.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57393r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56823'
  tag rid: 'SV-71083r1_rule'
  tag stig_id: 'SRG-OS-000374-GPOS-00159'
  tag gtitle: 'SRG-OS-000374-GPOS-00159'
  tag fix_id: 'F-61719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
