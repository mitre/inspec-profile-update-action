control 'SV-222492' do
  title 'The application must provide a report generation capability that supports on-demand audit review and analysis.'
  desc "The report generation capability must support on-demand review and analysis in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Report generation must be capable of generating on-demand (i.e., customizable, ad-hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective.

Audit reduction and report generation capabilities do not always reside on the same information system or within the same organizational entities conducting auditing activities. The audit reduction capability can include, for example, modern data mining techniques with advanced data filters to identify anomalous behavior in audit records. The report generation capability provided by the information system can generate customizable reports. Time ordering of audit records can be a significant issue if the granularity of the time stamp in the record is insufficient.

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding audit reduction (log record event filtering).

Access the application with user rights sufficient to read and filter audit records.

Navigate the application user interface and select the application functionality that provides access and interface to audit records and audit reporting.

If the application uses a centralized logging solution that provides immediate, customizable audit review and analysis functions, the requirement is not applicable.

Create an event report. Report data can be based on date ranges, times or events, or other criteria that could be used in an investigation. Use of data from previous checks for audit reduction is encouraged.

Review the report and ensure the data in the report coincides with event filters used to create the report.

If the application does not provide an immediate, ad-hoc audit review and analysis capability, this is a finding.'
  desc 'fix', 'Design or configure the application to provide an immediate audit review capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24162r493384_chk'
  tag severity: 'medium'
  tag gid: 'V-222492'
  tag rid: 'SV-222492r508029_rule'
  tag stig_id: 'APSC-DV-001180'
  tag gtitle: 'SRG-APP-000366'
  tag fix_id: 'F-24151r493385_fix'
  tag 'documentable'
  tag legacy: ['SV-84089', 'V-69467']
  tag cci: ['CCI-001878']
  tag nist: ['AU-7 a']
end
