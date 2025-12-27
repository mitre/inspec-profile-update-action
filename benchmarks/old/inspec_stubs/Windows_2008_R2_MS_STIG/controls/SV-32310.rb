control 'SV-32310' do
  title 'Ejection of removable NTFS media is not restricted to Administrators.'
  desc 'Removable hard drives can be formatted and ejected by others who are not members of the Administrators Group, if they are not properly configured.  Formatting and ejecting removable NTFS media should only be done by administrators.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Devices: Allowed to Format and Eject Removable Media” is not set to “Administrators”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon

Value Name:  AllocateDASD

Value Type:  REG_SZ
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Allowed to Format and Eject Removable Media” to “Administrators”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32922r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1171'
  tag rid: 'SV-32310r1_rule'
  tag gtitle: 'Format and Eject Removable Media'
  tag fix_id: 'F-113r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
