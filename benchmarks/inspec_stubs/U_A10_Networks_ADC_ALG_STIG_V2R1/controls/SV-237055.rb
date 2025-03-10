control 'SV-237055' do
  title 'The A10 Networks ADC must generate an alert to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The device generates an alert which notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.
Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The device must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel."
  desc 'check', 'Ask the device administrator which method is used to send messages when threats are detected. 

Review the device configuration.

If there is no method and target configured, this is a finding.'
  desc 'fix', 'These are two of the three possible methods of notification that can be configured.

The following command enables SNMP traps:

snmp-server enable traps

Note: This will enable sending all traps. 

The following command configures the SNMPv3 trap receiver (target):
 
snmp-server host trap-receiver version v3

Up to 16 trap receivers can be configured.

For security, SNMP and SNMP trap are disabled on all data interfaces. Use the enable-management command to enable SNMP on the management interface.

The following command configures log email settings:
logging email buffer number [num] time [minutes]
By default, emailing of log messages is disabled. If this is enabled, the buffer options have the following default values: number – 50, time – 10.

The following command configures an email filter:
logging email filter filter-num conditions operators [trigger]
Since there are alerts that require immediate action, use the "trigger" option. This immediately sends the messages rather than buffering them. 

The following command specifies the email address to which to email the log messages:
logging email-address [address]
More than one email address can be set.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40274r639610_chk'
  tag severity: 'medium'
  tag gid: 'V-237055'
  tag rid: 'SV-237055r639612_rule'
  tag stig_id: 'AADC-AG-000114'
  tag gtitle: 'SRG-NET-000392-ALG-000142'
  tag fix_id: 'F-40237r639611_fix'
  tag 'documentable'
  tag legacy: ['SV-82595', 'V-68105']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
