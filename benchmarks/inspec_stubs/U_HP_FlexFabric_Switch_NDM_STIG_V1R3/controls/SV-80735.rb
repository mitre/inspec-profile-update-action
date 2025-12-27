control 'SV-80735' do
  title 'The HP FlexFabric Switch must generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Determine if the HP FlexFabric Switch provides the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near-real-time.

[HP] display info-center

Information Center: Enabled
Console: Enabled
Monitor: Enabled
Log host: Enabled
    192.100.50.27,
    port number: 514, host facility: local7
Log buffer: Enabled
    Max buffer size 1024, current buffer size 512
    Current messages 66, dropped messages 0, overwritten messages 0
Log file: Enabled
Security log file: Enabled
Information timestamp format:
    Log host: Date
    Other output destination: Date

If the HP FlexFabric Switch does not provide the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near-real-time, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to generate an immediate real-time alert of all audit failure events requiring real-time alerts.

[HP] info-center enable'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66245'
  tag rid: 'SV-80735r1_rule'
  tag stig_id: 'HFFS-ND-000097'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-72321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
