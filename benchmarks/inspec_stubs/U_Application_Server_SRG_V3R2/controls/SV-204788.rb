control 'SV-204788' do
  title 'The application server must allocate log record storage capacity in accordance with organization-defined log record storage requirements.'
  desc 'The proper management of log records not only dictates proper archiving processes and procedures be established, it also requires allocating enough storage space to maintain the logs online for a defined period of time.

If adequate online log storage capacity is not maintained, intrusion monitoring, security investigations, and forensic analysis can be negatively affected.

It is important to keep a defined amount of logs online and readily available for investigative purposes. The logs may be stored on the application server until they can be archived to a log system or, in some instances, a Storage Area Networks (SAN).  Regardless of the method used, log record storage capacity must be sufficient to store log data when the data cannot be offloaded to a log system or SAN.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server creates log storage to buffer log data until offloading to a log data storage facility.

If the application server does not allocate storage for log data, this is a finding.'
  desc 'fix', 'Configure the application server to allocate storage for log data before offloading to a log data storage facility.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4908r283011_chk'
  tag severity: 'medium'
  tag gid: 'V-204788'
  tag rid: 'SV-204788r508029_rule'
  tag stig_id: 'SRG-APP-000357-AS-000038'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-4908r283012_fix'
  tag 'documentable'
  tag legacy: ['SV-71693', 'V-57421']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
