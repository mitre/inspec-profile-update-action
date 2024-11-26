control 'SV-223197' do
  title 'The Juniper SRX Services Gateway must generate log records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if log records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

While the Juniper SRX inherently has the capability to generate log records, by default only the high facility levels are captured and only to local files. 

Ensure at least one Syslog server and local files are configured to support requirements. However, the Syslog itself must also be configured to filter event records so it is not overwhelmed. A best practice when configuring the external Syslog server is to add similar log-prefixes to the log file names to help and researching of central Syslog server. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX).'
  desc 'check', 'Verify logging has been enabled and configured.

[edit] 
show system syslog

If at least one valid syslog host server and the syslog file names are not configured to capture "any" facility and "any" event, this is a finding.'
  desc 'fix', 'The following commands configure syslog to record any use of any command, including privileged commands. Configure Syslog and local backup files to capture DoD-defined auditable events. 

[edit]
set system syslog user * any emergency
set system syslog host <IP-syslog-server> any any
set system syslog host <IP-syslog-server> source-address <MGT-IP-Address>
set system syslog host <IP-syslog-server> log-prefix <host-name>
set system syslog file messages any info
set system syslog file messages authorization none
set system syslog file messages interactive-commands none 
set system syslog file messages daemon none 
set system syslog file User-Auth authorization any

set system syslog file interactive-commands interactive-commands any
set system syslog file processes daemon any
set system syslog file account-actions change-log any any
set file account-actions match “system login user”
set system syslog console any any'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24870r513281_chk'
  tag severity: 'low'
  tag gid: 'V-223197'
  tag rid: 'SV-223197r513283_rule'
  tag stig_id: 'JUSX-DM-000055'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-24858r513282_fix'
  tag 'documentable'
  tag legacy: ['SV-81061', 'V-66571']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
