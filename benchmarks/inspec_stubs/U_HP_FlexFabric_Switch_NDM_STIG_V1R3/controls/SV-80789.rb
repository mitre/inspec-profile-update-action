control 'SV-80789' do
  title 'The HP FlexFabric switch must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Determine if the HP FlexFabric Switch generates alerts that can be forwarded to the administrators and ISSO when accounts are created. 

[HP] display info-center

Information Center: Enabled
Console: Enabled
Monitor: Enabled
Log host: Enabled
    Source address interface: GigabitEthernet0/1
   192.168.16.102,
    port number: 514, host facility: local7

If the HP FlexFabric Switch is configured to use an authentication server which would perform this function, this is not a finding.

If alerts are not generated when accounts are created and forwarded to the administrators and ISSO, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to send a notification message to the to the syslog server when accounts are created.

[HP]  info-center loghost 192.168.16.102'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66299'
  tag rid: 'SV-80789r1_rule'
  tag stig_id: 'HFFS-ND-000142'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-72375r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
