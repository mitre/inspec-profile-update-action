control 'SV-80799' do
  title 'In the event that communications with the Syslog server is lost, the Juniper SRX Services Gateway must continue to queue traffic log records locally.'
  desc 'It is critical that when the network element is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

Since availability is an overriding concern given the role of the Juniper SRX in the enterprise, the system must not be configured to shut down in the event of a log processing failure. The system will be configured to log events to local files which will provide a log backup. If communication with the syslog server is lost or the server fails, the network device must continue to queue log records locally. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local log data with the collection server.

By default, both traffic log and system log events are sent to a local log file named messages. You can create a separate log file that contains only traffic log messages so that you do not need to filter for traffic log messages. This makes it easier to track usage patterns or troubleshoot issues for a specific policy. 

A best practice is to add log-prefixes to the log file names to help in researching the events and filters to prevent log overload. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX).'
  desc 'check', 'Verify logging has been enabled and configured.

[edit] 
show log <LOG-NAME> match "RT_FLOW_SESSION"

If a local log file or files is not configured to capture "RT_FLOW_SESSION" events, this is a finding.'
  desc 'fix', 'The following example commands configure local backup files to capture DoD-defined auditable events. 

[edit]
set system syslog file <LOG-NAME> any info
set system syslog file <LOG-NAME> match "RT_FLOW_SESSION "

Example:
set system syslog file<LOG-NAME> match "RT_FLOW_SESSION "'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66309'
  tag rid: 'SV-80799r1_rule'
  tag stig_id: 'JUSX-AG-000063'
  tag gtitle: 'SRG-NET-000089-ALG-000055'
  tag fix_id: 'F-72385r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
