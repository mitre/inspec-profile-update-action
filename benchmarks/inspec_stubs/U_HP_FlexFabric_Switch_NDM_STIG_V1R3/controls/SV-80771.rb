control 'SV-80771' do
  title 'The HP FlexFabric Switch must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Determine if the HP FlexFabric Switch is configured to use an external syslog server:

[HP] display info-center

Information Center: Enabled
Console: Enabled
Monitor: Enabled
Log host: Enabled
    Source address interface: M-GigabitEthernet0/0/0
    192.168.100.12,
    port number: 514, host facility: local7
 Log buffer: Enabled
    Max buffer size 1024, current buffer size 512
    Current messages 356, dropped messages 0, overwritten messages 0
Log file: Enabled
Security log file: Enabled
Information timestamp format:
    Log host: Date
    Other output destination: Date

If the HP FlexFabric Switch is not configure to use an external syslog server, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to forward its log to an external syslog server:

[HP] info-center loghost 192.168.100.12'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66281'
  tag rid: 'SV-80771r1_rule'
  tag stig_id: 'HFFS-ND-000127'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-72357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
