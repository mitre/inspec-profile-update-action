control 'SV-80691' do
  title 'The HP FlexFabric Switch must disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to network devices. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the device. Owners of inactive accounts will not notice if unauthorized access to their account has been obtained. 

Network devices need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if it automatically disables accounts after 35 days.

[HP] display password-control

Global password control configurations:

 User account idle time:  35 days

If accounts are not automatically disabled after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to automatically disable accounts after 35 days of inactivity:

[HP] password-control enable
[HP] password-control login idle-time 35'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66201'
  tag rid: 'SV-80691r1_rule'
  tag stig_id: 'HFFS-ND-000052'
  tag gtitle: 'SRG-APP-000163-NDM-000251'
  tag fix_id: 'F-72277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
