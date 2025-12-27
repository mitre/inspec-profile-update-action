control 'SV-253919' do
  title 'The Juniper EX switch must be configured to generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Determine if the network device generates an immediate alert of all audit failure events requiring real-time alerts.

Juniper network devices support monitoring the audit log storage partition (/var), monitoring the SNMP health status, or both. On devices supporting disk partition monitoring, verify the audit log partition (/var) free space is configured appropriately for the environment. For example, to generate "high disk usage" alerts at 80 percent capacity (20 percent free), and "full disk usage" at 90 percent capacity (10 percent free):
[edit chassis]
disk-partition /var {
    level full {
        free-space 10 percent;
    }
    level high {
        free-space 20 percent;
    }
}
Note: The configurable parameter is a percentage of free space remaining, not percentage used. "High" usage percent of remaining free space must be equal to, or greater than, the "full" usage percent of remaining free space.

For network devices supporting SNMP health monitoring, verify the rising and falling threshold values for monitored objects (e.g., CPU, memory, and disk storage usage). In the example below, any monitored object exceeding 75 percent usage will generate an alert. Another alert is generated when the usage falls below 74 percent. As configured in the example, Junos samples every 300 seconds. The falling threshold value must be less than the rising threshold value. Verify the thresholds are appropriate for the target environment.
[edit snmp]
health-monitor {
    interval 300;
    rising-threshold 75;
    falling-threshold 74;
}
Note: Monitored objects generate an event the first time they cross a threshold, not at every sample interval.

This requirement may be verified by configuration review or validated test results.

If an immediate alert of all audit failure events requiring real-time alerts is not generated, this is a finding.'
  desc 'fix', 'Configure the network device to generate an immediate real-time alert of all audit failure events requiring real-time alerts.

set chassis disk-partition /var level full free-space <0..100>
set chassis disk-partition /var level full free-space percent
set chassis disk-partition /var level high free-space <0..100>
set chassis disk-partition /var level high free-space percent
Note: "High" disk free-space value must be equal to or greater than "full" free-space value.

set snmp health-monitor interval <1..2147483647 seconds>
set snmp health-monitor rising-threshold <1..100 percent>
set snmp health-monitor falling-threshold <0..100 percent>
Note: Falling threshold value must be less than the rising-threshold value or commit fails.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57371r843788_chk'
  tag severity: 'medium'
  tag gid: 'V-253919'
  tag rid: 'SV-253919r843790_rule'
  tag stig_id: 'JUEX-NM-000420'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-57322r843789_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
