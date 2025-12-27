control 'SV-204824' do
  title 'The application server must generate log records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Changing privileges of a subject/object may cause a subject/object to gain or lose capabilities.  When successful/unsuccessful changes are made, the event needs to be logged.  By logging the event, the modification or attempted modification can be investigated to determine if it was performed inadvertently or maliciously.'
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records when successful/unsuccessful attempts are made to modify privileges.

If log records are not generated, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records when privileges are successfully or unsuccessfully modified.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4944r283113_chk'
  tag severity: 'medium'
  tag gid: 'V-204824'
  tag rid: 'SV-204824r508029_rule'
  tag stig_id: 'SRG-APP-000495-AS-000220'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-4944r283114_fix'
  tag 'documentable'
  tag legacy: ['SV-71711', 'V-57439']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
