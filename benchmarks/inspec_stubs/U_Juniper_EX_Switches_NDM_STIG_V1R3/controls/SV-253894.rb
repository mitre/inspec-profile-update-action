control 'SV-253894' do
  title 'The Juniper EX switch must be configured to generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., administrators or processes acting on behalf of administrators) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', %q(Determine if the network device generates audit records containing information that establishes the identity of any individual or process associated with the event. This requirement may be verified by demonstration or validated test results. 

Junos standard event log messages are configurable for time format, inclusion of logging facility and severity levels, and format. Setting "structured-data" automatically includes "explicit-priority" and "time-format year millisecond". Verify logging is enabled.

[edit system]
syslog {
    host <syslog IPv4 or IPv6 address> {
        any info;
        structured-data; <<< Includes 'explicit-priority' and 'time-format'
    }
    host <syslog IPv4 or IPv6 address> {
        any info;
        explicit-priority; <<< Includes logging facility and severity in standard format
    }
    file <file name> {
        any info; <<< Uses only standard format
    }
    time-format year; <<< Applied only to standard format
}
Note: In the example, events sent to the first external syslog server include the year and time is expressed in milliseconds. The second syslog server and the file both include the year, but time is expressed in seconds.

If the network device does not generate audit records containing information that establishes the identity of any individual or process associated with the event, this is a finding.)
  desc 'fix', "Configure the network device to generate audit records containing information that establishes the identity of any individual or process associated with the event.

set system syslog host <syslog IPv4 or IPv6 address> any info
set system syslog host <syslog IPv4 or IPv6 address> structured-data <<< Includes the 'explicit-priority' and 'time-format year millisecond' directives
set system syslog file <file name> any info
set system syslog file <file name> structured-data <<< Includes the 'explicit-priority' and 'time-format year millisecond' directives
-or-
set system syslog host <syslog IPv4 or IPv6 address> any info
set system syslog host <syslog IPv4 or IPv6 address> explicit-priority <<< Only if log level and severity are required
set system syslog file <file name> any info
set system syslog file <file name> explicit-priority <<< Only if log level and severity are required
set system syslog time-format year"
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57346r844935_chk'
  tag severity: 'medium'
  tag gid: 'V-253894'
  tag rid: 'SV-253894r879568_rule'
  tag stig_id: 'JUEX-NM-000170'
  tag gtitle: 'SRG-APP-000100-NDM-000230'
  tag fix_id: 'F-57297r843714_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
