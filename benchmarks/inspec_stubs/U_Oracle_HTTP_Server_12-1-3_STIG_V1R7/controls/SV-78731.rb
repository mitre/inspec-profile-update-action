control 'SV-78731' do
  title 'The log data and records from OHS must be backed up onto a different system or media.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', '1. Verify that the System Administrator backs up the files located in the $DOMAIN_HOME/servers/<componentName>/logs directory.

2. If the files located in the $DOMAIN_HOME/servers/<componentName>/logs directory, this is a finding.'
  desc 'fix', 'Have the System Administrator back up the files located in the $DOMAIN_HOME/servers/<componentName>/logs directory.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64241'
  tag rid: 'SV-78731r1_rule'
  tag stig_id: 'OH12-1X-000077'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-70171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
