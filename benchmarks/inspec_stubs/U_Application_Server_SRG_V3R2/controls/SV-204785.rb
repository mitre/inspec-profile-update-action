control 'SV-204785' do
  title 'The application server must provide access logging that ensures users who are granted a privileged role (or roles) have their privileged activity logged.'
  desc 'In order to be able to provide a forensic history of activity, the application server must ensure users who are granted a privileged role or those who utilize a separate distinct account when accessing privileged functions or data have their actions logged.

If privileged activity is not logged, no forensic logs can be used to establish accountability for privileged actions that occur on the system.'
  desc 'check', 'Review application server documentation and log configuration to verify the application server logs privileged activity.

If the application server is not configured to log privileged activity, this is a finding.'
  desc 'fix', 'Configure the application server to log privileged activity.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4905r283002_chk'
  tag severity: 'medium'
  tag gid: 'V-204785'
  tag rid: 'SV-204785r508029_rule'
  tag stig_id: 'SRG-APP-000343-AS-000030'
  tag gtitle: 'SRG-APP-000343'
  tag fix_id: 'F-4905r283003_fix'
  tag 'documentable'
  tag legacy: ['SV-71669', 'V-57397']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
