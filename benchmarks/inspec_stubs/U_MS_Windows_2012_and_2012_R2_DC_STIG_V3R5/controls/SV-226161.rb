control 'SV-226161' do
  title 'Access to the Windows Store must be turned off.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  Turning off access to the Windows Store will limit access to publicly available applications.'
  desc 'check', 'The Windows Store is not installed by default. If the \\Windows\\WinStore directory does not exist, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoUseStoreOpenWith

Type: REG_DWORD
Value: 1'
  desc 'fix', 'If the \\Windows\\WinStore directory exists, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off access to the Store" to "Enabled".   

Alternately, uninstall the "Desktop Experience" feature from Windows 2012.  This is located under "User Interfaces and Infrastructure" in the "Add Roles and Features Wizard".  The \\Windows\\WinStore directory may need to be manually deleted after this.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27863r475806_chk'
  tag severity: 'medium'
  tag gid: 'V-226161'
  tag rid: 'SV-226161r794423_rule'
  tag stig_id: 'WN12-CC-000030'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27851r475807_fix'
  tag 'documentable'
  tag legacy: ['SV-51609', 'V-36680']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
