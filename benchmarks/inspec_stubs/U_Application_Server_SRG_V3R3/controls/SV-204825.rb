control 'SV-204825' do
  title 'The application server must generate log records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Deleting privileges of a subject/object may cause a subject/object to gain or lose capabilities.  When successful and unsuccessful privilege deletions are made, the events need to be logged.  By logging the event, the modification or attempted modification can be investigated to determine if it was performed inadvertently or maliciously.'
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records when successful and unsuccessful attempts are made to delete privileges.

If log records are not generated, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records when privileges are successfully or unsuccessfully deleted.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4945r283116_chk'
  tag severity: 'medium'
  tag gid: 'V-204825'
  tag rid: 'SV-204825r508029_rule'
  tag stig_id: 'SRG-APP-000499-AS-000224'
  tag gtitle: 'SRG-APP-000499'
  tag fix_id: 'F-4945r283117_fix'
  tag 'documentable'
  tag legacy: ['SV-71713', 'V-57441']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
