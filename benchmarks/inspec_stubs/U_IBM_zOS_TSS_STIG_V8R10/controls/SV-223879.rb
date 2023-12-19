control 'SV-223879' do
  title 'The CA-TSS PTHRESH Control Option must be set to 2.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PTHRESH Control Option value is not set to PTHRESH(02), this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified following and proceed with the change.

PTHRESH(02)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25552r516036_chk'
  tag severity: 'medium'
  tag gid: 'V-223879'
  tag rid: 'SV-223879r877720_rule'
  tag stig_id: 'TSS0-ES-000060'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-25540r516037_fix'
  tag 'documentable'
  tag legacy: ['V-98465', 'SV-107569']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
