control 'SV-253893' do
  title 'The Juniper EX switch must be configured to produce audit records that contain information to establish the outcome of the event.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', %q(Determine if the network device is configured to produce audit records that contain information to establish the outcome of the event. 

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

If the network device does not produce audit records that contain information to establish the outcome of the event, this is a finding.)
  desc 'fix', "Configure the network device to produce audit records that contain information to establish the outcome of the event. 

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
  tag check_id: 'C-57345r843710_chk'
  tag severity: 'medium'
  tag gid: 'V-253893'
  tag rid: 'SV-253893r843712_rule'
  tag stig_id: 'JUEX-NM-000160'
  tag gtitle: 'SRG-APP-000099-NDM-000229'
  tag fix_id: 'F-57296r843711_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
