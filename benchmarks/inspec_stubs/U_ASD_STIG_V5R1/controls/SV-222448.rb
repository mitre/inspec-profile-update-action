control 'SV-222448' do
  title 'The application must provide audit record generation capability for connecting system IP addresses.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

The IP addresses of remote systems that connect to the application are an important aspect of identifying the sources of application activity. Recording these IP addresses in the application logs provides forensic evidence and aids in investigating and identifying sources of malicious behavior related to security events.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify where audit logs are stored.

Review audit logs and determine if the IP address information of systems that connect to the application is kept in the logs.

If connecting IP addresses are not seen in the logs, connect to the application remotely and review the logs to determine if the connection was logged.

If the IP addresses of the systems that connect to the application are not recorded in the logs, this is a finding.'
  desc 'fix', 'Configure the application or application server to log all connecting IP address information'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24118r493252_chk'
  tag severity: 'medium'
  tag gid: 'V-222448'
  tag rid: 'SV-222448r508029_rule'
  tag stig_id: 'APSC-DV-000690'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24107r493253_fix'
  tag 'documentable'
  tag legacy: ['V-69377', 'SV-83999']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
