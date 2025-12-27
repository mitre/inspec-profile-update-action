control 'SV-224921' do
  title 'Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.'
  desc 'Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in hardened UNC paths before allowing access to them. This aids in preventing tampering with or spoofing of connections to these paths.'
  desc 'check', 'This requirement is applicable to domain-joined systems. For standalone systems, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths\\

Value Name: \\\\*\\NETLOGON
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\SYSVOL
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Additional entries would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network Provider >> "Hardened UNC Paths" to "Enabled" with at least the following configured in "Hardened UNC Paths": (click the "Show" button to display)

Value Name: \\\\*\\SYSVOL
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\NETLOGON
Value: RequireMutualAuthentication=1, RequireIntegrity=1'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26612r465665_chk'
  tag severity: 'medium'
  tag gid: 'V-224921'
  tag rid: 'SV-224921r569186_rule'
  tag stig_id: 'WN16-CC-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26600r465666_fix'
  tag 'documentable'
  tag legacy: ['SV-88161', 'V-73509']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
