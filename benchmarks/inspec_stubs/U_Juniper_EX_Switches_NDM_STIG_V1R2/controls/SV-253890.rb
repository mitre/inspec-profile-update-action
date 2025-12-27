control 'SV-253890' do
  title 'The Juniper EX switch must be configured to produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', %q(Determine if the network device is configured to produce audit records containing information to establish when (date and time) the events occurred. 

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

If the network device does not produce audit records containing information to establish when the events occurred, this is a finding.)
  desc 'fix', "Configure the network device to produce audit records containing information to establish when (date and time) the events occurred.

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
  tag check_id: 'C-57342r843701_chk'
  tag severity: 'medium'
  tag gid: 'V-253890'
  tag rid: 'SV-253890r843703_rule'
  tag stig_id: 'JUEX-NM-000130'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-57293r843702_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
