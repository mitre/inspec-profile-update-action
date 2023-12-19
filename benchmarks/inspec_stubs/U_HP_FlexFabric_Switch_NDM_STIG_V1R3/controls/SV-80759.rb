control 'SV-80759' do
  title 'The HP FlexFabric Switch must generate audit records when successful/unsuccessful attempts to delete administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the HP FlexFabric Switch (e.g., module or policy filter).'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch: 

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66269'
  tag rid: 'SV-80759r1_rule'
  tag stig_id: 'HFFS-ND-000121'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-72345r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
