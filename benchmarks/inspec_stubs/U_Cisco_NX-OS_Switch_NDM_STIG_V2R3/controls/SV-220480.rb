control 'SV-220480' do
  title 'The Cisco switch must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must disconnect the session.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Review the Cisco switch configuration to verify that it enforces the limit of three consecutive invalid logon attempts as shown in the example below:

ssh login-attempts 3

If the Cisco switch is not configured to enforce the limit of three consecutive invalid logon attempts, this is a finding.

NOTE: The NX-OS switch does not lock out the account, it disconnects the session. The AAA server will lock out the user account on three failed attempts.'
  desc 'fix', 'Configure the Cisco switch to enforce the limit of three consecutive invalid logon attempts as shown in the example below:

SW2(config)# ssh login-attempts 3'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22195r802430_chk'
  tag severity: 'medium'
  tag gid: 'V-220480'
  tag rid: 'SV-220480r802432_rule'
  tag stig_id: 'CISC-ND-000150'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-22184r802431_fix'
  tag 'documentable'
  tag legacy: ['SV-110607', 'V-101503']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
