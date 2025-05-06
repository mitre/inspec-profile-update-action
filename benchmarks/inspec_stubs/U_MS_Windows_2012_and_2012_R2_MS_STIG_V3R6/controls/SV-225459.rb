control 'SV-225459' do
  title 'The computer account password must not be prevented from being reset.'
  desc 'Computer account passwords are changed automatically on a regular basis.  Disabling automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  A new password for the computer account will be generated every 30 days.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: DisablePasswordChange

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Disable machine account password changes" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27158r471719_chk'
  tag severity: 'low'
  tag gid: 'V-225459'
  tag rid: 'SV-225459r569185_rule'
  tag stig_id: 'WN12-SO-000015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27146r471720_fix'
  tag 'documentable'
  tag legacy: ['SV-52873', 'V-1165']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
