control 'SV-95953' do
  title 'The WebSphere Application Server must allocate JVM log record storage capacity in accordance with organization-defined log record storage requirements.'
  desc 'JVM logs are logs used to store application and runtime related events, rather than audit related events. They are mainly used to diagnose application or runtime bugs. But sometimes they may be useful in providing more context when correlated with audit related events. 

The proper management of log records not only dictates proper archiving processes and procedures be established, it also requires allocating enough storage space to maintain the logs online for a defined period of time.

If adequate online log storage capacity is not maintained, intrusion monitoring, security investigations, and forensic analysis can be negatively affected.

It is important to keep a defined amount of logs online and readily available for investigative purposes. The logs may be stored on the application server until they can be archived to a log system or, in some instances, a Storage Area Networks (SAN). Regardless of the method used, log record storage capacity must be sufficient to store log data when the data cannot be offloaded to a log system or SAN.'
  desc 'check', 'Review System Security Plan documentation.

Identify the JVM log size and rotation settings based on component log policy.

From the administrative console, navigate to Troubleshooting >> Logs and Trace.

Choose [server name].

Click on the server name to select it.

Click "JVM" Logs.

For "System.out" verify "File Size" is selected and "Maximum size" and "Maximum Historical Log Files" are set according to the System Security Plan. 

For "System.err" verify "File Size" is selected and "Maximum size" and "Maximum Historical Log Files" are set according to the System Security Plan. 

If log size and log history retention settings for "System.err" and "System.out" are not set as per the System Security Plan, this is a finding.'
  desc 'fix', 'Identify JVM log size and history retention based on component log policy.

Document those values in the System Security Plan.

From the administrative console, navigate to Troubleshooting >> Logs and Trace.

Select each [server name].

Click "JVM" Logs. 

Under "System.out", "Log Rotation", select "File size" in the "Maximum Size" entry field, enter the maximum log size based on policy.

Under "System.err", "Log Rotation", select "File Size" in the "Maximum Size" entry field, enter the maximum log size based on policy.

Click "OK".

Click "Save".'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81239'
  tag rid: 'SV-95953r1_rule'
  tag stig_id: 'WBSP-AS-000580'
  tag gtitle: 'SRG-APP-000357-AS-000038'
  tag fix_id: 'F-88019r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
