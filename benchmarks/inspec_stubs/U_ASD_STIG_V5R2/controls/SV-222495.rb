control 'SV-222495' do
  title 'The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.'
  desc 'If the audit reduction capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding audit reduction (log record event filtering).

Access the application with user rights sufficient to read and filter audit records.

Navigate the application user interface and select the application functionality that provides access and interface to audit records and audit reduction (event filtering).

If the application uses a centralized logging solution that performs the audit reduction (event filtering) functions, the requirement is not applicable.

Examine the log files; take note of dates and times of events such as logon events.

Note: dates and times as well as the original content and any unique record identifiers.

Record the identifying information as well as the dates and times and content of the audit records.

Apply filters to reduce the amount of audit records displayed to just the logon events for the day.

Review the records and ensure nothing in the records has changed. Once validated, clear the filter and review the records again to validate nothing changed within the audit record itself.

If the application of event filters modifies the original log records, this is a finding.'
  desc 'fix', 'Configure the application to not alter original log content or time ordering of audit records.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24165r493393_chk'
  tag severity: 'medium'
  tag gid: 'V-222495'
  tag rid: 'SV-222495r849446_rule'
  tag stig_id: 'APSC-DV-001210'
  tag gtitle: 'SRG-APP-000369'
  tag fix_id: 'F-24154r493394_fix'
  tag 'documentable'
  tag legacy: ['SV-84095', 'V-69473']
  tag cci: ['CCI-001881']
  tag nist: ['AU-7 b']
end
