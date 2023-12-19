control 'SV-80937' do
  title 'The Juniper SRX Services Gateway must generate alerts to the management console and generate a log record that can be forwarded to the ISSO and designated system administrators when the local accounts (i.e., the account of last resort or root account) are deleted.'
  desc 'An authorized insider or individual who maliciously delete a local account could gain immediate access from a remote location to privileged information on a critical security device. Sending an alert to the administrators and ISSO when this action occurs greatly reduces the risk that accounts will be surreptitiously deleted.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites). The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. Alerts must be sent immediately to designated individuals. Alerts may be sent via NMS, SIEM, Syslog configuration, SNMP trap or notice, or manned console message.

Although, based on policy, administrator accounts must be deleted on the AAA server, this requirement addresses the deletion of unauthorized accounts on the Juniper SRX itself. This does not negate the need to address this requirement on the AAA server and the event monitoring server (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers).

Accounts can be disabled by configuring the account with the built-in login class "unauthorized". When the command is reissued with a different login class, the account is enabled.'
  desc 'check', 'Verify the device is configured to display change-log events of severity info.

[edit]
show system syslog

If the system is not configured to display account deletion actions on the management console and generate an event log message to the Syslog server and a local file, this is a finding.'
  desc 'fix', "The following commands configure the device to immediately display a message to any currently logged on administrator's console when changes are made to the configuration. This is an example method. Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

[edit]
set system syslog users * change-log <info | any> 
set system syslog host <IP-syslog-server> any any
set system syslog file account-actions change-log any any"
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67093r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66447'
  tag rid: 'SV-80937r1_rule'
  tag stig_id: 'JUSX-DM-000022'
  tag gtitle: 'SRG-APP-000294-NDM-000278'
  tag fix_id: 'F-72523r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
