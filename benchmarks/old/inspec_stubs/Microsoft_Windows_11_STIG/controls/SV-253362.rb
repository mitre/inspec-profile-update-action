control 'SV-253362' do
  title 'Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.'
  desc 'Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in Hardened UNC paths before allowing access them. This aids in preventing tampering with or spoofing of connections to these paths.'
  desc 'check', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

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
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network Provider >> "Hardened UNC Paths" to "Enabled" with at least the following configured in "Hardened UNC Paths:" (click the "Show" button to display).

Value Name: \\\\*\\SYSVOL
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\\\*\\NETLOGON
Value: RequireMutualAuthentication=1, RequireIntegrity=1'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56815r829168_chk'
  tag severity: 'medium'
  tag gid: 'V-253362'
  tag rid: 'SV-253362r829170_rule'
  tag stig_id: 'WN11-CC-000050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56765r829169_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
