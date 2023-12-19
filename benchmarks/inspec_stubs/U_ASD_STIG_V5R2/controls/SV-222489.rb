control 'SV-222489' do
  title 'The application must provide an audit reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis."
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture and logging configuration.

Identify the application components and the logs associated with the components.

If the application utilizes a centralized logging system that provides the capability to generate reports based on filtered log events, this requirement is not applicable.

Using the relevant application features for generating reports and/or searching application data, (this is usually executed directly within a logging utility or within a reports feature or function) configure a filter based on any of the security criteria provided below.

Alternatively, you can use security-oriented criteria provided by the application administrator.

Once the data filter has been selected, filter the audit event data so only filtered data is displayed and generate the report.

The report can be any combination of screen-based, soft copy, or a printed report.

Criteria:
Users: e.g., specific users or groups
Event types:
Event dates and time:
System resources involved: e.g., application components or modules.
IP addresses:
Information objects accessed:
Event level categories: e.g., high, critical, warning, error

If the application does not provide on demand reports based on the filtered audit event data, this is a finding.'
  desc 'fix', 'Configure the application to generate soft copy, hard copy and/or screen-based reports based on the selected filtered event data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24159r493375_chk'
  tag severity: 'medium'
  tag gid: 'V-222489'
  tag rid: 'SV-222489r849440_rule'
  tag stig_id: 'APSC-DV-001150'
  tag gtitle: 'SRG-APP-000181'
  tag fix_id: 'F-24148r493376_fix'
  tag 'documentable'
  tag legacy: ['SV-84083', 'V-69461']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
