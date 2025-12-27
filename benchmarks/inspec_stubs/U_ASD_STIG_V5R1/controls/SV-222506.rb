control 'SV-222506' do
  title 'The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained.

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify log functionality and locations of log files.

If the application does not include a built-in backup capability for backing up its own audit records, this requirement is not applicable.

Access the management interface for configuring application audit logs and review the backup settings.

If the application backup settings are not configured to backup application audit records every 7 days, this is a finding.'
  desc 'fix', 'Configure application backup settings to backup application audit logs every 7 days.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24176r493426_chk'
  tag severity: 'medium'
  tag gid: 'V-222506'
  tag rid: 'SV-222506r508029_rule'
  tag stig_id: 'APSC-DV-001340'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-24165r493427_fix'
  tag 'documentable'
  tag legacy: ['SV-84117', 'V-69495']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
