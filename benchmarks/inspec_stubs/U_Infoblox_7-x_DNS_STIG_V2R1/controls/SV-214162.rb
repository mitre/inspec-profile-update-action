control 'SV-214162' do
  title 'The Infoblox system audit records must be backed up at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on a defined frequency helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', 'Navigate to Grid >> Grid Manager >> Grid Properties >> Monitoring tab.

If "Log to External Syslog Servers" is enabled, an External Syslog Server must be configured. 

If no external SYSLOG server is available verify local procedure to retain audit logs. Logs can be downloaded by navigation to Administration >> Logs >> Audit Log tab and pressing the "Download" button.

When complete, click "Cancel" to exit the "Properties" screen.

If neither an external SYSLOG server is configured, or a local policy is in place to store audit logs, this is a finding.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Grid Properties >> Monitoring tab.

Enable "Log to External Syslog Servers" and configure an "External Syslog Server".
Review Infoblox audit records on the remote SYSLOG server to validate operation.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15377r295752_chk'
  tag severity: 'medium'
  tag gid: 'V-214162'
  tag rid: 'SV-214162r612370_rule'
  tag stig_id: 'IDNS-7X-000120'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-15375r295753_fix'
  tag 'documentable'
  tag legacy: ['V-68521', 'SV-83011']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
