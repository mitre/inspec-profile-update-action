control 'SV-95961' do
  title 'The WebSphere Application Server audit subsystem failure action must be set to Log warning.'
  desc 'Logs are essential to monitor the health of the system, investigate changes that occurred to the system, or investigate a security incident. When log processing fails, the events during the failure can be lost. To minimize the timeframe of the log failure, an alert needs to be sent to the SA and ISSO at a minimum.

Log processing failures include, but are not limited to, failures in the application server log capturing mechanisms or log storage capacity being reached or exceeded. WebSphere must be set to log warnings that the audit subsystem has failed or is in danger or failing so action can be taken to correct the issue.'
  desc 'check', 'In the administrative console, navigate to Security >> Security auditing.

If "Audit subsystem failure action" is not set to "Log Warning", this is a finding.'
  desc 'fix', 'In the administrative console, navigate to Security >> Security auditing.

Click the "Audit subsystem failure action" dropdown box.

Select "Log Warning".

Click "Apply".

Click "Save" to save the configuration.

Restart the DMGR and all JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81247'
  tag rid: 'SV-95961r1_rule'
  tag stig_id: 'WBSP-AS-000650'
  tag gtitle: 'SRG-APP-000108-AS-000067'
  tag fix_id: 'F-88027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
