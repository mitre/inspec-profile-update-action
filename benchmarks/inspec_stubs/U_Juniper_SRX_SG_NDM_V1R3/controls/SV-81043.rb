control 'SV-81043' do
  title 'For local accounts created on the device, the Juniper SRX Services Gateway must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.

Juniper SRX is unable to comply with the 15-minute time period part of this control.'
  desc 'check', 'Verify the number of unsuccessful logon attempts is set to 3.

[edit]
show system login retry-options 

If the number of unsuccessful logon attempts is set to 3, this is a finding.'
  desc 'fix', 'Configure the number of unsuccessful logon attempts for all login account, globally.

[edit]
set system login retry-options tries-before-disconnect 3'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67199r1_chk'
  tag severity: 'low'
  tag gid: 'V-66553'
  tag rid: 'SV-81043r1_rule'
  tag stig_id: 'JUSX-DM-000030'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-72629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
