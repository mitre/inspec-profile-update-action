control 'SV-222490' do
  title 'The application must provide an audit reduction capability that supports on-demand audit review and analysis.'
  desc "The ability to perform on-demand audit review and analysis, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Audit reduction is a technique used to reduce the volume of audit records in order to facilitate a manual review. Audit reduction does not alter original audit records. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as-needed) reports.

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

If the application does not provide an audit reduction capability that supports on-demand reports based on the filtered audit event data, this is a finding.'
  desc 'fix', 'Configure the application to log to a centralized auditing capability that provides on-demand reports based on the filtered audit event data or design or configure the application to meet the requirement.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24160r493378_chk'
  tag severity: 'medium'
  tag gid: 'V-222490'
  tag rid: 'SV-222490r879737_rule'
  tag stig_id: 'APSC-DV-001160'
  tag gtitle: 'SRG-APP-000364'
  tag fix_id: 'F-24149r493379_fix'
  tag 'documentable'
  tag legacy: ['SV-84085', 'V-69463']
  tag cci: ['CCI-001875']
  tag nist: ['AU-7 a']
end
