control 'SV-95955' do
  title 'The WebSphere Application Server must allocate audit log record storage capacity in accordance with organization-defined log record storage requirements.'
  desc 'The proper management of log records not only dictates proper archiving processes and procedures be established, it also requires allocating enough storage space to maintain the logs online for a defined period of time.

If adequate online log storage capacity is not maintained, intrusion monitoring, security investigations, and forensic analysis can be negatively affected.

It is important to keep a defined amount of logs online and readily available for investigative purposes. The logs may be stored on the application server until they can be archived to a log system or, in some instances, a Storage Area Networks (SAN). Regardless of the method used, log record storage capacity must be sufficient to store log data when the data cannot be offloaded to a log system or SAN.'
  desc 'check', 'Review System Security Plan documentation.

Identify the Audit Service Provider log size and rotation settings based on component log policy.

From administrative console, click Security >> Security auditing >> Audit service provider.

Select each [audit_service_provider_name].

If "Audit Log Size" and "Max Number of Audit Log Files" are not configured as per the System Security Plan, this is a finding.'
  desc 'fix', 'Identify Audit Service Provider log size and history retention based on component log policy.

Document those values in the System Security Plan.

From administrative console, click Security >> Security auditing >>Related Items>> Audit service provider >> [audit_service_provider_name].

Under Audit log file size specify the size of the file in MB as defined by your policy.

Under "Maximum number of audit logs files", specify the maximum number of logs you want to keep on the file system as defined by your policy.

Click "OK".

Click "Save".'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81241'
  tag rid: 'SV-95955r1_rule'
  tag stig_id: 'WBSP-AS-000590'
  tag gtitle: 'SRG-APP-000357-AS-000038'
  tag fix_id: 'F-88021r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
