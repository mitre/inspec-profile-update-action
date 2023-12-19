control 'SV-253889' do
  title 'The Juniper device must be configured to produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', %q(Determine if the network device produces audit log records containing sufficient information to establish what type of event occurred. 

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

If the network device does not produce audit log records containing sufficient information to establish what type of event occurred, this is a finding.)
  desc 'fix', "Configure the network device to produce audit log records containing sufficient information to establish what type of event occurred.

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
  tag check_id: 'C-57341r843698_chk'
  tag severity: 'medium'
  tag gid: 'V-253889'
  tag rid: 'SV-253889r843700_rule'
  tag stig_id: 'JUEX-NM-000120'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-57292r843699_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
