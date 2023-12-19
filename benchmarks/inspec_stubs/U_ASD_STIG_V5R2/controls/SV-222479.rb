control 'SV-222479' do
  title 'The application must implement transaction recovery logs when transaction based.'
  desc 'Without required logging and access control, security issues related to data changes will not be identified. This could lead to security compromises such as data misuse, unauthorized changes, or unauthorized access.

Transaction logs contain a sequential record of all changes to the database. Using a transaction log helps with maintaining application availability and aids in speedy recovery. Transactional logging should be enabled whenever the application database offers the transactional logging capability.'
  desc 'check', 'Review the application documentation and interview the application administrator.  Have the application administrator provide configuration settings that demonstrate transaction logging is enabled.

Review configuration settings for the location of transaction specific logs and verify transaction logs exist and the log records access and changes to the data.

If the application is not configured to utilize transaction logging, this is a finding.'
  desc 'fix', 'Configure the application database to utilize transactional logging.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24149r493345_chk'
  tag severity: 'medium'
  tag gid: 'V-222479'
  tag rid: 'SV-222479r508029_rule'
  tag stig_id: 'APSC-DV-001040'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-24138r493346_fix'
  tag 'documentable'
  tag legacy: ['V-69441', 'SV-84063']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
