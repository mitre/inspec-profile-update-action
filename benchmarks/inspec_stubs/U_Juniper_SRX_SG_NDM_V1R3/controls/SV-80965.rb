control 'SV-80965' do
  title 'The Juniper SRX Services Gateway must enable log record generation for DoD-defined auditable events within the Juniper SRX Service Gateway.'
  desc 'Without the capability to generate log records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

DoD has defined the list of events for which the device will provide an audit record generation capability. These events as the following which are individually called out in other CCIs: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.

While the Juniper SRX inherently has the capability to generate log records, by default only the high facility levels are captured by default to local files. 

Ensure the Syslog server and local files are configured to support requirements. A best practice when configuring the external Syslog server is to add similar log-prefixes to the log file names to help and researching of central Syslog server. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX).'
  desc 'check', 'Verify logging has been enabled and configured.

[edit] show system syslog

If a syslog host server has not been configured to capture DoD-defined auditable events, this is a finding.'
  desc 'fix', 'The following example commands configure Syslog and local backup files to capture DoD-defined auditable events. 

[edit]
set system syslog user * any emergency
set system syslog host <IP-syslog-server> any any
set system syslog host <IP-syslog-server> source-address <MGT-IP-Address>
set system syslog host <IP-syslog-server> log-prefix <host-name>
set system syslog file messages any info
set system syslog file messages authorization info
set system syslog file User-Auth authorization any
set system syslog file User-Auth interactive-commands any
set system syslog file audit interactive-commands any
set system syslog file processes daemon any
set system syslog console any any
set system syslog file account-actions change-log any any
set system syslog file account-actions match “system login user”'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66475'
  tag rid: 'SV-80965r1_rule'
  tag stig_id: 'JUSX-DM-000038'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-72551r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
