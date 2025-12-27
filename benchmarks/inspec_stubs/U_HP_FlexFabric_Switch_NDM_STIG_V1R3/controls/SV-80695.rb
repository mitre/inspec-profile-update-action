control 'SV-80695' do
  title 'The HP FlexFabric Switch must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the HP FlexFabric Switch allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Determine if the HP FlexFabric Switch  prohibits password reuse for a minimum of five generations.

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled
 Password aging:                      Enabled (90 days)
 Password length:                     Enabled (10 characters)
 Password composition:                Enabled (1 types, 1 characters per type)
 Password history:                    Enabled (max history records: 4)

If the HP FlexFabric Switch or its associated authentication server does not prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch server to prohibit password reuse for a minimum of five generations.

[HP] password-control enable
[HP] password-control history 5'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66205'
  tag rid: 'SV-80695r1_rule'
  tag stig_id: 'HFFS-ND-000054'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-72281r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
