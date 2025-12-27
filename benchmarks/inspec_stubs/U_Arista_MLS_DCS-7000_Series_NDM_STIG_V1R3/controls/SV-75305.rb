control 'SV-75305' do
  title 'The Arista Multilayer Switch must produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'Review the device configuration and verify that logging is enabled with sufficient detail to establish what type of event occurred.

If logging is not enabled or does not provide sufficient detail, this is a finding.

To determine if logging is enabled, enter:

switch#show logging

The output must show logging as enabled, with a logging level of informational or debugging.'
  desc 'fix', 'Enable logging on the switch with sufficient detail to establish what type of event occurred.

To configure logging to a remote syslog server at the informational level, enter:

switch#config
switch(config)#logging host [ip address]
switch(config)#logging trap informational'
  impact 0.3
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61795r1_chk'
  tag severity: 'low'
  tag gid: 'V-60849'
  tag rid: 'SV-75305r1_rule'
  tag stig_id: 'AMLS-NM-000190'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-66559r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
