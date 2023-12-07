control 'SV-225013' do
  title 'Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.'
  desc "The Windows Security Account Manager (SAM) stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials."
  desc 'check', 'This applies to member servers and standalone or nondomain-joined systems. It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)'
  desc 'fix', 'Navigate to the policy Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict clients allowed to make remote calls to SAM". 

Select "Edit Security" to configure the "Security descriptor:".

Add "Administrators" in "Group or user names:" if it is not already listed (this is the default).

Select "Administrators" in "Group or user names:".

Select "Allow" for "Remote Access" in "Permissions for "Administrators".

Click "OK".

The "Security descriptor:" must be populated with "O:BAG:BAD:(A;;RC;;;BA) for the policy to be enforced.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26704r857268_chk'
  tag severity: 'medium'
  tag gid: 'V-225013'
  tag rid: 'SV-225013r877392_rule'
  tag stig_id: 'WN16-MS-000310'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26692r857269_fix'
  tag 'documentable'
  tag legacy: ['SV-88341', 'V-73677']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
