control 'SV-80631' do
  title 'The HP FlexFabric Switch must automatically disable accounts after a 35-day period of account inactivity.'
  desc 'Since the accounts in the HP FlexFabric Switch are privileged or system-level accounts, account management is vital to the security of the HP FlexFabric Switch. Inactive accounts could be reactivated or compromised by unauthorized users, allowing exploitation of vulnerabilities and undetected access to the HP FlexFabric Switch. 

This control does not include emergency administration accounts, which are meant for access to the HP FlexFabric Switch components in case of network failure.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if it automatically disables accounts after 35 days.

[HP] display password-control

Global password control configurations:

User account idle time:  35 days

If accounts are not automatically disabled after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to automatically disable accounts after 35 days of inactivity:

[HP]password-control login idle-time 35'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66787r2_chk'
  tag severity: 'low'
  tag gid: 'V-66141'
  tag rid: 'SV-80631r1_rule'
  tag stig_id: 'HFFS-ND-000008'
  tag gtitle: 'SRG-APP-000025-NDM-000207'
  tag fix_id: 'F-72217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
