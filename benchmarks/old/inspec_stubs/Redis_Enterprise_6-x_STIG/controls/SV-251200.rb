control 'SV-251200' do
  title 'Redis Enterprise DBMS must be configurable to overwrite audit log records, oldest first (First-In-First-Out [FIFO]), in the event of unavailability of space for more audit log records.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the DBMS must continue generating audit records, if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the DBMS must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations.'
  desc 'check', 'Redis Enterprise uses the default logrotate daemon to schedule rotation of logs stored on the operating system. The configuration of log rotation may be found at /etc/logrotate.d.

By default, the log rotation should occur on a daily basis. Redis Labs recommends sending log files to a remote logging server so that they can be more effectively maintained.

To check the log rotation policy, perform the following steps:
1. sudo cat /etc/logrotate.conf (The location of the log rotation configuration may vary depending on operating system distribution.)
2. Investigate the log rotation policy to verify that the appropriate policy is applied for all logs.

Check to verify that log rotation is not disabled and is appropriate for the application by investigating the logrotated configuration. If log rotation is not enabled or is not configured appropriately, this is a finding.'
  desc 'fix', 'Redis Enterprise uses the default logrotate daemon to schedule rotation of logs stored on the operating system. The configuration of log rotation may be found at /etc/logrotate.d.

By default, the log rotation should occur on a daily basis. Redis Labs recommends sending log files to a remote logging server so that they can be more effectively maintained.

To modify the log rotation policy perform the following steps:
1. sudo vi /etc/logrotate.conf (The location of the log rotation configuration may vary depending on operating system distribution.)
2. Modify the log rotation configuration to meet the needs of the application.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54635r804788_chk'
  tag severity: 'medium'
  tag gid: 'V-251200'
  tag rid: 'SV-251200r804790_rule'
  tag stig_id: 'RD6X-00-006000'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag fix_id: 'F-54589r804789_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
