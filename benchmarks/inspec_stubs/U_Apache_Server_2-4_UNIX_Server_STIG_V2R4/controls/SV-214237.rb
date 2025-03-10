control 'SV-214237' do
  title 'The log data and records from the Apache web server must be backed up onto a different system or media.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to ensure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Interview the Information System Security Officer, System Administrator, Web Manager, Webmaster, or developers as necessary to determine whether a tested and verifiable backup strategy has been implemented for web server software and all web server data files.

Proposed questions:
- Who maintains the backup and recovery procedures?
- Do you have a copy of the backup and recovery procedures?
- Where is the off-site backup location?
- Is the contingency plan documented?
- When was the last time the contingency plan was tested?
- Are the test dates and results documented?

If there is not a backup and recovery process for the web server, this is a finding.'
  desc 'fix', 'Document the web server backup procedures.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15451r276971_chk'
  tag severity: 'medium'
  tag gid: 'V-214237'
  tag rid: 'SV-214237r879582_rule'
  tag stig_id: 'AS24-U1-000210'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-15449r276972_fix'
  tag 'documentable'
  tag legacy: ['SV-102723', 'V-92635']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
