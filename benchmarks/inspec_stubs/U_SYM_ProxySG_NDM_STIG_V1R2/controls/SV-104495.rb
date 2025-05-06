control 'SV-104495' do
  title 'Symantec ProxySG must enable event access logging.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.

ProxySG generates the required logs both automatically and with additional configuration. See the check section for more details. Logs are written locally up to the allowed log size and overwrite the oldest log entries first when the log size limit is reached. The retention of logs written to remote syslog systems are governed by those remote systems.'
  desc 'check', 'Verify event access logging is enabled.

1. Log on to the Web Management Console.
2. Click Maintenance >> Event Logging and ensure that the log level is set to at least "Configuration Events".

If event access logging is not enabled, this is a finding.'
  desc 'fix', 'Event access logging is enabled by default. In order to enable audit logging, both "Event Logging" and "Admin Access Layer" logging must be configured. All information is always logged, but a display filter can be set to view a subset of the information.

1. Log on to the Web Management Console.
2. Click Maintenance >> Event Logging and ensure that the log level is set to at least "Configuration Events".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94665'
  tag rid: 'SV-104495r1_rule'
  tag stig_id: 'SYMP-NM-000070'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-100783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
