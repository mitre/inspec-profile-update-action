control 'SV-237059' do
  title 'The A10 Networks ADC must, at a minimum, off-load audit log records onto a centralized log server.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the device is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Review the device configuration.

The following command shows the portion of the device configuration that includes the string "host":
show run | inc host

If the output does not display the "logging auditlog host" commands, this is a finding.

The following command shows the logging policy:
show log policy

If Syslog logging is disabled, this is a finding.'
  desc 'fix', 'Since the Audit log is separate from the Event log, it must have its own target to write messages to:
logging auditlog host [ipaddr | hostname][facility facility-name]

“ipaddr | hostname” is the IP address or hostname of the server.
“facility-name” is the name of a log facility.'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40278r639622_chk'
  tag severity: 'low'
  tag gid: 'V-237059'
  tag rid: 'SV-237059r639624_rule'
  tag stig_id: 'AADC-AG-000140'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-40241r639623_fix'
  tag 'documentable'
  tag legacy: ['SV-82509', 'V-68019']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
