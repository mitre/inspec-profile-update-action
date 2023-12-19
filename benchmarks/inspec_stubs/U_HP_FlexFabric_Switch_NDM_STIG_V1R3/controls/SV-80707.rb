control 'SV-80707' do
  title 'The HP FlexFabric Switch must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the HP FlexFabric Switch does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised. 

This requirement does not include emergency administration accounts which are meant for access to the HP FlexFabric Switch in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Determine if the HP FlexFabric Switch enforces a 60-day maximum password lifetime.  

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled
 Password aging:                      Enabled (60 days)

If the HP FlexFabric Switch or its associated authentication server does not enforce a 60-day maximum password lifetime, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce a 60-day maximum password lifetime.

[HP]password-control enable
[HP]password-control aging 60'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66217'
  tag rid: 'SV-80707r1_rule'
  tag stig_id: 'HFFS-ND-000063'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-72293r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
