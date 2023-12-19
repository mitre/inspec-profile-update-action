control 'SV-223880' do
  title 'The CA-TSS NPPTHRESH Control Option must be properly set.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PTHRESH Control Option value is not set to NPPTHRESH(02), this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified following and proceed with the change.

NPPTHRESH(02)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25553r516039_chk'
  tag severity: 'medium'
  tag gid: 'V-223880'
  tag rid: 'SV-223880r561402_rule'
  tag stig_id: 'TSS0-ES-000070'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-25541r516040_fix'
  tag 'documentable'
  tag legacy: ['V-98467', 'SV-107571']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
