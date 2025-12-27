control 'SV-80915' do
  title 'The IDPS must send an alert to, at a minimum, the ISSO and ISSM when intrusion detection events are detected that indicate a compromise or potential for compromise.'
  desc 'Without an alert, security personnel may be unaware of intrusion detection incidents that require immediate action and this delay may result in the loss or compromise of information.

In accordance with CCI-001242, the IDPS is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The Juniper SRX IDPS can be configured for email alerts.'
  desc 'check', 'Verify an attack group or rule is configured.

[edit]
show security idp policies

If an attack group or rule is not implemented to detect root-level intrusion attacks or the match condition is not configured for an alert, this is a finding.'
  desc 'fix', 'Create a custom rule that identifies the Junos application which is prohibited on the network. 

Add the option "alert" onto the rule to send an alert when that rule is invoked. Alerts should be sent only on critical and other site-selected items to prevent an excess of alerts.

[edit]
set security idp idp-policy recommended rulebase-ips rule-1 then notification log-attacks alert'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66425'
  tag rid: 'SV-80915r1_rule'
  tag stig_id: 'JUSX-IP-000023'
  tag gtitle: 'SRG-NET-000392-IDPS-00214'
  tag fix_id: 'F-72501r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
