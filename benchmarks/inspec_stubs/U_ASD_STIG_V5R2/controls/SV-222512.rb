control 'SV-222512' do
  title 'The application must audit who makes configuration changes to the application.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after-the-fact.

If application configuration is maintained by using a text editor to modify a configuration file, this function may be delegated to an operating system file monitoring/auditing capability.'
  desc 'check', 'Review the application documentation and configuration settings.

Access the application configuration settings interface as a privileged user.

Make configuration changes to the application.

Review the application audit logs and ensure a log entry is made identifying the privileged user account that was used to make the changes.

If application configuration is maintained by using a text editor to modify a configuration file, modify the configuration file with a text editor. Review the system logs and ensure a log entry is made for the file modification that identifies the user that was used to make the changes.

If the user account is not logged, or is a group account such as "root", this is a finding.

If the user account used to make the changes is not logged in the audit records, this is a finding.'
  desc 'fix', 'Configure the application to create log entries that can be used to identify the user accounts that make application configuration changes.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24182r493444_chk'
  tag severity: 'medium'
  tag gid: 'V-222512'
  tag rid: 'SV-222512r849452_rule'
  tag stig_id: 'APSC-DV-001420'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-24171r493445_fix'
  tag 'documentable'
  tag legacy: ['SV-84129', 'V-69507']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
