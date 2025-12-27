control 'SV-48060' do
  title 'Ejection of removable NTFS media must be restricted to Administrators.'
  desc 'Removable hard drives can be formatted and ejected by others who are not members of the Administrators Group, if they are not properly configured.  Formatting and ejecting removable NTFS media must only be done by administrators.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Devices: Allowed to Format and Eject Removable Media" is not set to " Administrators", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon

Value Name: AllocateDASD

Value Type: REG_SZ
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Allowed to Format and Eject Removable Media" to "Administrators".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1171'
  tag rid: 'SV-48060r1_rule'
  tag stig_id: 'WN08-SO-000011'
  tag gtitle: 'Format and Eject Removable Media'
  tag fix_id: 'F-41198r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
