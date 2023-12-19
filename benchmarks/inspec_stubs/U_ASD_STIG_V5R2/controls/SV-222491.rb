control 'SV-222491' do
  title 'The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  desc 'If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.

This requirement is specific to applications with audit reduction capabilities.'
  desc 'check', 'Review application documentation and interview application administrator for details regarding audit reduction (log record event filtering).

Access the application with user rights sufficient to read and filter audit records.

Navigate the application user interface and select the application functionality that provides access and interface to audit records and audit reduction (event filtering).

If the application uses a centralized logging solution that performs the audit reduction (event filtering) functions, the requirement is not applicable.

Examine the log files; take note of dates and times of events such as logon events.

Note: dates and times as well as the original content and any unique record identifiers.

Record the identifying information as well as the dates and times and content of the audit records.

Apply filters to reduce the amount of audit records displayed to just the logon events for the day.

Review the records and ensure the application provides the ability to filter on audit events.

If the application does not provide an audit reduction (event filtering) capability, this is a finding.'
  desc 'fix', 'Configure the application to provide an audit reduction capability that supports forensic investigations.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24161r493381_chk'
  tag severity: 'medium'
  tag gid: 'V-222491'
  tag rid: 'SV-222491r849442_rule'
  tag stig_id: 'APSC-DV-001170'
  tag gtitle: 'SRG-APP-000365'
  tag fix_id: 'F-24150r493382_fix'
  tag 'documentable'
  tag legacy: ['SV-84087', 'V-69465']
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
