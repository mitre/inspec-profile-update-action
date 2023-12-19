control 'SV-222496' do
  title 'The application must provide a report generation capability that does not alter original content or time ordering of audit records.'
  desc 'If the audit report generation capability alters the original content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

The report generation capability provided by the application can generate customizable reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding audit reduction (log record event filtering).

Access the application with user rights sufficient to read and filter audit records.

Navigate the application user interface and select the application functionality that provides access and interface to audit records and audit reduction (event filtering).

If the application does not provide a report generation capability, the requirement is not applicable.

Examine the log files; take note of dates and times of events such as logon events.

Note: dates and times as well as the original content and any unique record identifiers.

Record the identifying information as well as the dates and times and content of the audit records.

Apply filters to reduce the amount of audit records displayed to just the logon events for the day.

Review the records and ensure nothing in the records has changed. Once validated, clear the filter and review the records again to validate nothing changed within the audit record itself.

If the application of event filters modifies the original log records, this is a finding.'
  desc 'fix', 'Configure and design the application to not modify source logs when filtering events.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24166r493396_chk'
  tag severity: 'medium'
  tag gid: 'V-222496'
  tag rid: 'SV-222496r508029_rule'
  tag stig_id: 'APSC-DV-001220'
  tag gtitle: 'SRG-APP-000370'
  tag fix_id: 'F-24155r493397_fix'
  tag 'documentable'
  tag legacy: ['V-69475', 'SV-84097']
  tag cci: ['CCI-001882']
  tag nist: ['AU-7 b']
end
