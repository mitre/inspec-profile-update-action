control 'SV-204729' do
  title 'The application server must shut down by default upon log failure (unless availability is an overriding concern).'
  desc 'It is critical that, when a system is at risk of failing to process logs, it detects and takes action to mitigate the failure. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.  During a failure, the application server must be configured to shut down unless the application server is part of a high availability system.

When availability is an overriding concern, other approved actions in response to a log failure are as follows: 

(i) If the failure was caused by the lack of log record storage capacity, the application must continue generating log records if possible (automatically restarting the log service if necessary), overwriting the oldest log records in a first-in-first-out manner.

(ii) If log records are sent to a centralized collection server and communication with this server is lost or the server fails, the application must queue log records locally until communication is restored or until the log records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local log data with the collection server.'
  desc 'check', 'If the application server is a high availability system, this finding is NA.

Review the application server configuration settings to determine if the application server is configured to shut down on a log failure.

If the application server is not configured to shut down on a log failure, this is a finding.'
  desc 'fix', 'If the application server is a high availability system, this finding is NA.

Configure the application server to shut down on a log failure.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4849r282834_chk'
  tag severity: 'medium'
  tag gid: 'V-204729'
  tag rid: 'SV-204729r508029_rule'
  tag stig_id: 'SRG-APP-000109-AS-000068'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-4849r282835_fix'
  tag 'documentable'
  tag legacy: ['SV-46477', 'V-35190']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
