control 'SV-79603' do
  title 'The DataPower Gateway must generate alerts that can be forwarded to the administrators and ISSO when accounts are created.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. Verify that "Trap Event Subscriptions" include the Event Subscription code that indicates account creation: 0x8240001c.

On the "Trap and Notification Targets" tab, verify that this configuration includes the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when account creation events occur.

On the Main tab, confirm that the "Administrative state" is set to "enabled". Additionally, confirm that that the run time state (shown at the top of the page after the text "SNMP Settings") indicates in brackets that the SNMP object is in an "up" state.

Confirm that when an account is created, an appropriate 0x8240001c "Configuration added" event appears in the DataPower audit log (In the WebGUI go to Status >> View Logs >> Audit Log), and that an appropriate notification is sent by the SNMP server specified on the "Trap and Notification Targets" tab of the DataPower SNMP Settings.

If this event message does not appear in the audit log, this is a finding.'
  desc 'fix', %q(In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. 

On the Trap Event Subscriptions tab, set to "on" the "Enable Default Event Subscriptions" option >> set to "warning" the "Minimum Priority" option >> configure "Trap Event Subscriptions" to include an Event Subscription that indicates account creation by adding a 0x8240001c Event Subscription.

Example log result: "[conf][success][0x8240001c] (SYSTEM:default:*:*): user 'admin' Configuration added"

On the "Trap and Notification Targets" tab, add the Remote Host Address and Remote Port of an approved SNMP server that generates alerts that will be forwarded to the administrators and ISSO when accounts are created.

On the Main tab, set the "Administrative state" to "enabled" >> Click "Save Configuration".)
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65113'
  tag rid: 'SV-79603r1_rule'
  tag stig_id: 'WSDP-NM-000077'
  tag gtitle: 'SRG-APP-000291-NDM-000275'
  tag fix_id: 'F-71053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
