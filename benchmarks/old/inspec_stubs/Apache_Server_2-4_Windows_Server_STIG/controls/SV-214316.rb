control 'SV-214316' do
  title 'The log data and records from the Apache web server must be backed up onto a different system or media.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to ensure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Interview the Information System Security Officer (ISSO), System Administrator (SA), Web Manager, Webmaster, or developers as necessary to determine whether a tested and verifiable backup strategy has been implemented for web server software as well as all web server data files.

Proposed Questions:
Who maintains the backup and recovery procedures?
Do you have a copy of the backup and recovery procedures?
Where is the off-site backup location?
Is the contingency plan documented?
When was the last time the contingency plan was tested?
Are the test dates and results documented?

If there is not a backup and recovery process for the web server, this is a finding.'
  desc 'fix', 'Document the web server backup procedures.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15528r277451_chk'
  tag severity: 'medium'
  tag gid: 'V-214316'
  tag rid: 'SV-214316r879582_rule'
  tag stig_id: 'AS24-W1-000210'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-15526r277452_fix'
  tag 'documentable'
  tag legacy: ['SV-102453', 'V-92365']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
