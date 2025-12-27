control 'SV-80719' do
  title 'The HP FlexFabric Switch must generate an immediate alert for account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes. 

In order to detect and respond to events that affect network administrator accessibility and device processing, network devices must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', "Enable info-center feature on the HP FlexFabric Switch: 

[HP] info-center enable

Note:  By default, the information center is enabled. Account enabling actions on the SUT generates an automatic log entry in the system's log."
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66229'
  tag rid: 'SV-80719r1_rule'
  tag stig_id: 'HFFS-ND-000086'
  tag gtitle: 'SRG-APP-000320-NDM-000284'
  tag fix_id: 'F-72305r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
