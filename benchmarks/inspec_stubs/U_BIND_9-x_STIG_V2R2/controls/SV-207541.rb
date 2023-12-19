control 'SV-207541' do
  title 'The BIND 9.x server logging configuration must be configured to generate audit records for all DoD-defined auditable events to a local file by enabling triggers for all events with a severity of info, notice, warning, error, and critical for all DNS components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 

The DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Verify the name server is configured to generate all DoD-defined audit records.

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
severity info;
};
};

If a channel is not configured to log messages with the severity of info and higher, this is a finding.

Note: "info" is the lowest severity level and will automatically log all messages with a severity of "info" or higher.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "severity" sub statement to the "channel" statement.

Configure the "severity" sub statement to "info"

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7796r539069_chk'
  tag severity: 'low'
  tag gid: 'V-207541'
  tag rid: 'SV-207541r612253_rule'
  tag stig_id: 'BIND-9X-001020'
  tag gtitle: 'SRG-APP-000089-DNS-000005'
  tag fix_id: 'F-7796r283678_fix'
  tag 'documentable'
  tag legacy: ['SV-87005', 'V-72381']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
