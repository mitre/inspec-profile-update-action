control 'SV-225455' do
  title 'Ejection of removable NTFS media must be restricted to Administrators.'
  desc 'Removable hard drives, if they are not properly configured, can be formatted and ejected by users who are not members of the Administrators Group.  Formatting and ejecting removable NTFS media must only be done by administrators.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: AllocateDASD

Value Type: REG_SZ
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Allowed to format and eject removable media" to "Administrators".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27154r471707_chk'
  tag severity: 'medium'
  tag gid: 'V-225455'
  tag rid: 'SV-225455r569185_rule'
  tag stig_id: 'WN12-SO-000011'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27142r471708_fix'
  tag 'documentable'
  tag legacy: ['SV-52875', 'V-1171']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
