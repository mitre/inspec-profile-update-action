control 'SV-222439' do
  title 'For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.'
  desc 'Without the ability to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded.

Audit trails are time-correlated if the time stamps in the individual audit records can be reliably related to the time stamps in other audit records to achieve a time ordering of the records within organization-defined level of tolerance.

This requirement applies to applications which provide the capability to compile system-wide audit records for multiple systems or system components. However, all applications must provide the relevant log details that are used to aggregate the information.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Determine if the application has the ability to compile audit records from multiple systems or system components.

If the application does not provide log aggregation services, this requirement is not applicable.

Identify the systems that comprise the application.

Access each system comprising the application or a random sample of several application systems. Review the application logs and obtain date and time stamps for several random audit events. Record the information.

Access the server providing the log aggregation. Access the application logs that have been written to the server and compare the samples obtained from the application systems to the aggregated logs. Ensure the dates and time stamps correlate with one another.

If the log dates and times do not correlate when the logs are aggregated, this is a finding.'
  desc 'fix', 'Configure the application to correlate time stamps when aggregating audit records.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24109r561231_chk'
  tag severity: 'medium'
  tag gid: 'V-222439'
  tag rid: 'SV-222439r561233_rule'
  tag stig_id: 'APSC-DV-000600'
  tag gtitle: 'SRG-APP-000086'
  tag fix_id: 'F-24098r561232_fix'
  tag 'documentable'
  tag legacy: ['SV-83981', 'V-69359']
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
