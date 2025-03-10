control 'SV-203726' do
  title 'The operating system must require devices to re-authenticate when changing authenticators.'
  desc 'Without re-authentication, devices may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to change device authenticators, it is critical the device re-authenticate.'
  desc 'check', 'Verify the operating system requires devices to re-authenticate when changing authenticators. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require devices to re-authenticate when changing authenticators.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3851r375185_chk'
  tag severity: 'medium'
  tag gid: 'V-203726'
  tag rid: 'SV-203726r851797_rule'
  tag stig_id: 'SRG-OS-000374-GPOS-00159'
  tag gtitle: 'SRG-OS-000374'
  tag fix_id: 'F-3851r375186_fix'
  tag 'documentable'
  tag legacy: ['SV-71083', 'V-56823']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
