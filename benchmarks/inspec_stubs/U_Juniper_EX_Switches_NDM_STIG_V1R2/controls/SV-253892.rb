control 'SV-253892' do
  title 'The Juniper EX switch must be configured to produce audit log records containing information to establish the source of events.'
  desc 'To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event. The source may be a component, module, or process within the device or an external session, administrator, or device.

Associating information about where the source of the event occurred provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', %q(Determine if the network device is configured to produce audit records containing information to establish the source (apparent cause) of the event. 

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

If the network device does not produce audit records containing information to establish the source of the event, this is a finding.)
  desc 'fix', "Configure the network device to produce audit records containing information to establish the source of the event.

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
  tag check_id: 'C-57344r843707_chk'
  tag severity: 'medium'
  tag gid: 'V-253892'
  tag rid: 'SV-253892r843709_rule'
  tag stig_id: 'JUEX-NM-000150'
  tag gtitle: 'SRG-APP-000098-NDM-000228'
  tag fix_id: 'F-57295r843708_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
