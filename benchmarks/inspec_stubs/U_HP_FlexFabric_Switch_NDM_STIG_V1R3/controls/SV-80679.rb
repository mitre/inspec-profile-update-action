control 'SV-80679' do
  title 'The HP FlexFabric Switch must use internal system clocks to generate time stamps for audit records.'
  desc "In order to determine what is happening within the network infrastructure or to resolve and trace an attack, the HP FlexFabric Switch must support the organization's capability to correlate the audit log data from multiple network devices to acquire a clear understanding of events. In order to correlate auditable events, time stamps are needed on all of the log records.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. (Note that the internal clock is required to be synchronized with authoritative time sources by other requirements.)"
  desc 'check', 'Determine if the HP FlexFabric Switch is configured to use internal system clocks to generate time stamps for audit records.

[HP] display clock

06:13:14 MDT Wed 08/05/2015
Time Zone : test minus 05:00:00
Summer Time : MDT 02:00:00 March second Sunday 02:00:00 November first Sunday 01:00:00

If the switch is not configured to use internal system clocks to generate time stamps for audit records, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to use internal system clocks to generate time stamps for audit records.
<HP> clock datetime 06:13:00 08/05/2015'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66189'
  tag rid: 'SV-80679r1_rule'
  tag stig_id: 'HFFS-ND-000035'
  tag gtitle: 'SRG-APP-000116-NDM-000234'
  tag fix_id: 'F-72265r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
