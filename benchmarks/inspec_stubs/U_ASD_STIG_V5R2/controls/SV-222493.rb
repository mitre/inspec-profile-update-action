control 'SV-222493' do
  title 'The application must provide a report generation capability that supports on-demand reporting requirements.'
  desc "The report generation capability must support on-demand reporting in order to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

The report generation capability provided by the application must be capable of generating on-demand (i.e., customizable, ad-hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective.

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements."
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding audit reduction (log record event filtering).

Access the application with user rights sufficient to read and filter audit records.

Navigate the application user interface and select the application functionality that provides access and interface to audit records and audit reduction (event filtering).

If the application uses a centralized logging solution that provides immediate, customizable, ad-hoc report generation functions, the requirement is not applicable.

Create an event report. Report data can be based on date ranges, times or events, or other criteria that could be used in an investigation. Use of data from previous checks for audit reduction is encouraged.

Review the report and ensure the data in the report coincides with event filters used to create the report.

If the application does not provide customizable, immediate, ad-hoc audit log reporting, this is a finding.'
  desc 'fix', 'Design or configure the application to provide an on-demand report generation capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24163r493387_chk'
  tag severity: 'medium'
  tag gid: 'V-222493'
  tag rid: 'SV-222493r849444_rule'
  tag stig_id: 'APSC-DV-001190'
  tag gtitle: 'SRG-APP-000367'
  tag fix_id: 'F-24152r493388_fix'
  tag 'documentable'
  tag legacy: ['SV-84091', 'V-69469']
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end
