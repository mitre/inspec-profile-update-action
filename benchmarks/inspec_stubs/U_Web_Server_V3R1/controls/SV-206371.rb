control 'SV-206371' do
  title 'The log data and records from the web server must be backed up onto a different system or media.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server log records are backed up onto an unrelated system or media than the system being logged.

If the web server logs are not backed up onto a different system or media than the system being logged, this is a finding.'
  desc 'fix', 'Configure the web server logs to be backed up onto a different system or media other than the system being logged.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6632r377705_chk'
  tag severity: 'medium'
  tag gid: 'V-206371'
  tag rid: 'SV-206371r395838_rule'
  tag stig_id: 'SRG-APP-000125-WSR-000071'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-6632r377706_fix'
  tag 'documentable'
  tag legacy: ['SV-54251', 'V-41674']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
