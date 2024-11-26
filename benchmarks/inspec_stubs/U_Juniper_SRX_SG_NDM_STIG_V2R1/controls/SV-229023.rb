control 'SV-229023' do
  title 'In the event that communications with the events server is lost, the Juniper SRX Services Gateway must continue to queue log records locally.'
  desc 'It is critical that when the network device is at risk of failing to process logs as required, it take action to mitigate the failure. Log processing failures include: software/hardware errors; failures in the log capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to log failure depend upon the nature of the failure mode. 

Since availability is an overriding concern given the role of the Juniper SRX in the enterprise, the system must not be configured to shut down in the event of a log processing failure. The system will be configured to log events to local files, which will provide a log backup. If communication with the Syslog server is lost or the server fails, the network device must continue to queue log records locally. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local log data with the collection server.

A best practice is to add log-prefixes to the log file names to help in researching the events and filters to prevent log overload. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX). Thus, the Juniper SRX will inherently and continuously capture events to local files to guard against the loss of connectivity to the primary and secondary events server.'
  desc 'check', 'Verify logging has been enabled and configured to capture to local log files in case connection with the primary and secondary log servers is lost.

[edit] 
show system syslog

If local log files are not configured to capture events, this is a finding.'
  desc 'fix', 'The following example commands configure local backup files to capture DoD-defined auditable events. 

[edit]
set system syslog file messages any info
set system syslog file messages authorization none
set system syslog file messages interactive-commands none 
set system syslog file messages daemon none 
set system syslog file User-Auth authorization any
set system syslog file interactive-commands interactive-commands any
set system syslog file processes daemon any
set system syslog file account-actions change-log any any
set file account-actions match â€œsystem login userâ€?
set system syslog console any any'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-31338r518245_chk'
  tag severity: 'medium'
  tag gid: 'V-229023'
  tag rid: 'SV-229023r518247_rule'
  tag stig_id: 'JUSX-DM-000061'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31315r518246_fix'
  tag 'documentable'
  tag legacy: ['SV-80971', 'V-66481']
  tag cci: ['CCI-000366', 'CCI-001686']
  tag nist: ['CM-6 b', 'AC-2 (4)']
end
