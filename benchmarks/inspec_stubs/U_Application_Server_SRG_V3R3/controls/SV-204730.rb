control 'SV-204730' do
  title 'The application server must be configured to fail over to another system in the event of log subsystem failure.'
  desc 'This requirement is dependent upon system MAC and availability.  If the system MAC and availability do not specify redundancy requirements, this requirement is NA.

It is critical that, when a system is at risk of failing to process logs as required, it detects and takes action to mitigate the failure.
 
Application servers must be capable of failing over to another system which can handle application and logging functions upon detection of an application log processing failure. This will allow continual operation of the application and logging functions while minimizing the loss of operation for the users and loss of log data.'
  desc 'check', "If the system MAC level and availability do not require redundancy, this requirement is NA.

Review the system's accreditation documentation to determine system MAC and confidentiality requirements.  Review application server configuration settings to determine if the application server is configured to fail over operation to another system when the log subsystem fails to operate.

If the system MAC level requires redundancy and the application server is not configured to fail over to another system which can handle application and log functions when a log subsystem failure occurs, this is a finding."
  desc 'fix', 'If the system MAC level and availability do not require redundancy, this requirement is NA.

Configure the application server to fail over to another system which can handle log functions when the logging subsystem fails.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4850r282837_chk'
  tag severity: 'medium'
  tag gid: 'V-204730'
  tag rid: 'SV-204730r508029_rule'
  tag stig_id: 'SRG-APP-000109-AS-000070'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-4850r282838_fix'
  tag 'documentable'
  tag legacy: ['SV-46478', 'V-35191']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
