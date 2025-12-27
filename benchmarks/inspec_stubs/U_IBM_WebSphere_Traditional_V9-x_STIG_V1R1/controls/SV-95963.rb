control 'SV-95963' do
  title 'The WebSphere Application Server must shut down by default upon log failure (unless availability is an overriding concern).'
  desc 'It is critical that, when a system is at risk of failing to process logs, it detects and takes action to mitigate the failure. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. During a failure, the application server must be configured to shut down unless the application server is part of a high availability system or availability is an overriding concern.

When availability is an overriding concern, other approved actions in response to a log failure include: 

(i) If the failure was caused by the lack of log record storage capacity, the application must continue generating log records if possible (automatically restarting the log service if necessary), overwriting the oldest log records in a first-in-first-out manner.

(ii) If log records are sent to a centralized collection server and communication with this server is lost or the server fails, the application must queue log records locally until communication is restored or until the log records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local log data with the collection server.

If the server will continue to process without any logging mitigations in place and the availability of the server is not critical to the success of the mission, the server must be configured to shut down on log failure.'
  desc 'check', 'If the System Security Plan documentation specifies system availability is an overriding concern, this requirement is NA.

In the admin console click Security >> Security Auditing.

If "Audit subsystem failure action" is not set to "Terminate", this is a finding.'
  desc 'fix', 'In the admin console click Security >> Security Auditing.

Set "Audit subsystem failure action" to "Terminate".

Restart the DMGR and all JVMs.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80935r1_chk'
  tag severity: 'low'
  tag gid: 'V-81249'
  tag rid: 'SV-95963r1_rule'
  tag stig_id: 'WBSP-AS-000660'
  tag gtitle: 'SRG-APP-000109-AS-000068'
  tag fix_id: 'F-88029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
