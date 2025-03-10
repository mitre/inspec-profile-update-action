control 'SV-204738' do
  title 'The application server must back up log records at least every seven days onto a different system or system component than the system or component being logged.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media from the system the application server is actually running on helps to assure that in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Review the application server configuration to determine if the application server backs up log records every seven days onto a different system or media from the system being logged.

If the application server does not back up log records every seven days onto a different system or media from the system being logged, this is a finding.'
  desc 'fix', 'Configure the application server to back up log records every seven days onto a different system or media from the system being logged.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4858r282861_chk'
  tag severity: 'medium'
  tag gid: 'V-204738'
  tag rid: 'SV-204738r879582_rule'
  tag stig_id: 'SRG-APP-000125-AS-000084'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-4858r282862_fix'
  tag 'documentable'
  tag legacy: ['V-35216', 'SV-46503']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
