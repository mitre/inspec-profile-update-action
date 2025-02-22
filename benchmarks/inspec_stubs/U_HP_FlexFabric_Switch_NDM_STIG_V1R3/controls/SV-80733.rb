control 'SV-80733' do
  title 'The HP FlexFabric Switch must generate an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. This could lead to the loss of audit information. Note that while the HP FlexFabric Switch must generate the alert, notification may be done by a management server.'
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
  desc 'fix', 'Configure the HP FlexFabric Switch to generate an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

[HP] info-center security-logfile alarm-threshold 75'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66243'
  tag rid: 'SV-80733r1_rule'
  tag stig_id: 'HFFS-ND-000096'
  tag gtitle: 'SRG-APP-000359-NDM-000294'
  tag fix_id: 'F-72319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
