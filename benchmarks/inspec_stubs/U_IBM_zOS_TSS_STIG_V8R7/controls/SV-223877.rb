control 'SV-223877' do
  title 'The CA-TSS NPWRTHRESH Control Option must be properly set.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the NPWRTHRESH Control Option value is not set to NPWRTHRESH(02), this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified following and proceed with the change.

NPWRTHRESH(02)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25550r516030_chk'
  tag severity: 'medium'
  tag gid: 'V-223877'
  tag rid: 'SV-223877r561402_rule'
  tag stig_id: 'TSS0-ES-000040'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-25538r516031_fix'
  tag 'documentable'
  tag legacy: ['SV-107565', 'V-98461']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
