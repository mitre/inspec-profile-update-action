control 'SV-222494' do
  title 'The application must provide a report generation capability that supports after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements.'
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding audit reduction (log record event filtering).

Access the application with user rights sufficient to read and filter audit records.

Navigate the application user interface and select the application functionality that provides access and interface to audit records and audit reduction (event filtering).

If the application uses a centralized logging solution that performs the report generation functions, the requirement is not applicable.

Create an event report. Report data can be based on date ranges, times or events, or other criteria that could be used in an investigation. Use of data from previous checks for audit reduction is encouraged.

Review the report and ensure the data in the report coincides with event filters used to create the report.

If the application does not have a report generation capability that supports after the fact security investigations, this is a finding.'
  desc 'fix', 'Design or configure the application to provide after-the-fact report generation capability or utilize a centralized utility designed for the purpose of log management and reporting.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24164r493390_chk'
  tag severity: 'medium'
  tag gid: 'V-222494'
  tag rid: 'SV-222494r849445_rule'
  tag stig_id: 'APSC-DV-001200'
  tag gtitle: 'SRG-APP-000368'
  tag fix_id: 'F-24153r493391_fix'
  tag 'documentable'
  tag legacy: ['SV-84093', 'V-69471']
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
