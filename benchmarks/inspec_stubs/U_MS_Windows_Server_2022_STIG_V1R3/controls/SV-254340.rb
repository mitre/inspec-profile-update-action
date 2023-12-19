control 'SV-254340' do
  title 'Windows Server 2022 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.'
  desc 'Additional security requirements are applied to UNC paths specified in hardened UNC paths before allowing access to them. This aids in preventing tampering with or spoofing of connections to these paths.'
  desc 'check', 'This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths\\

Value Name: \\\\*\\NETLOGON
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\SYSVOL
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Additional entries would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network Provider >> Hardened UNC Paths" to "Enabled" with at least the following configured in "Hardened UNC Paths" (click the "Show" button to display):

Value Name: \\\\*\\SYSVOL
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\NETLOGON
Value: RequireMutualAuthentication=1, RequireIntegrity=1'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57825r848834_chk'
  tag severity: 'medium'
  tag gid: 'V-254340'
  tag rid: 'SV-254340r848836_rule'
  tag stig_id: 'WN22-CC-000080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57776r848835_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
