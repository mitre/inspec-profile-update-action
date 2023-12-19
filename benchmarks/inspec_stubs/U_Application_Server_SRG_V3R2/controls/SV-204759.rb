control 'SV-204759' do
  title 'The application server must provide a log reduction capability that supports on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including after the log data has been subjected to log reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

Log reduction is a process that manipulates collected log information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad-hoc, and as needed) reports.

Instead of the application server providing the log reduction function; it is also accepted practice to configure the application server to send its logs to a centralized log system that can be used to provide the log reduction with reporting capability. Security Incident Event Management (SIEM) systems are an example of such a solution.

To fully understand and investigate an incident within the components of the application server, the application server, must be configured to provide log reduction and on-demand reporting or be configured to send its logs to a centralized log system."
  desc 'check', 'Review application server product documentation and server configuration to determine if the application server is configured to provide log reduction with on-demand reporting.

If the application server is not configured to provide log reduction with on-demand reporting, or is not configured to send its logs to a centralized log system, this is a finding.'
  desc 'fix', 'Configure the application server to provide and utilize log reduction with on-demand reporting or configure the application server to send its logs to a centralized log log system that provides log reduction and on-demand reporting functions.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4879r282924_chk'
  tag severity: 'medium'
  tag gid: 'V-204759'
  tag rid: 'SV-204759r508029_rule'
  tag stig_id: 'SRG-APP-000181-AS-000255'
  tag gtitle: 'SRG-APP-000181'
  tag fix_id: 'F-4879r282925_fix'
  tag 'documentable'
  tag legacy: ['V-57527', 'SV-71803']
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
end
