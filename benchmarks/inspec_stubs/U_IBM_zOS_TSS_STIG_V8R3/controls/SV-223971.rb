control 'SV-223971' do
  title 'The CA-TSS PTHRESH Control Option must be properly set.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the PTHRESH Control Option value is not set to "PTHRESH(2)", this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified following and proceed with the change.

PTHRESH(2)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25644r516312_chk'
  tag severity: 'medium'
  tag gid: 'V-223971'
  tag rid: 'SV-223971r561402_rule'
  tag stig_id: 'TSS0-ES-000980'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-25632r516313_fix'
  tag 'documentable'
  tag legacy: ['V-98649', 'SV-107753']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
