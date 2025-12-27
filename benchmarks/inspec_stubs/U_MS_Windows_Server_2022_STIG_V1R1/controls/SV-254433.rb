control 'SV-254433' do
  title 'Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems.'
  desc "The Windows SAM stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials."
  desc 'check', 'This applies to member servers and standalone or nondomain-joined systems; it is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)'
  desc 'fix', 'Navigate to the policy Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network access: Restrict clients allowed to make remote calls to SAM. 

Select "Edit Security" to configure the "Security descriptor:".

Add "Administrators" in "Group or user names:" if it is not already listed (this is the default).

Select "Administrators" in "Group or user names:".

Select "Allow" for "Remote Access" in "Permissions for "Administrators".

Click "OK".

The "Security descriptor:" must be populated with "O:BAG:BAD:(A;;RC;;;BA) for the policy to be enforced.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57918r849113_chk'
  tag severity: 'medium'
  tag gid: 'V-254433'
  tag rid: 'SV-254433r849115_rule'
  tag stig_id: 'WN22-MS-000060'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57869r849114_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
