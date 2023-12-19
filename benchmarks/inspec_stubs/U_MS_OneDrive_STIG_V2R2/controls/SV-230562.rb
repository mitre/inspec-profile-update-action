control 'SV-230562' do
  title 'OneDrive must only allow synchronizing of accounts for DoD organization instances.'
  desc 'OneDrive provides access to external services for data storage, which must be restricted to authorized instances if enabled. Configuring this setting will restrict synchronizing of OneDrive accounts to DoD organization instances.'
  desc 'check', "If the organization is using a DoD instance of OneDrive, verify synchronizing is only allowed to the organization's DoD instance.

If the organization does not have an instance of OneDrive, verify this is configured with the noted dummy entry to prevent synchronizing with other instances.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\OneDrive\\AllowTenantList\\

Value Name: Organization's Tenant GUID

Value Type: REG_SZ
Value: Organization's Tenant GUID

If the organization does not have an instance of OneDrive, the Value Name and Value must be 1111-2222-3333-4444.

If it is not, this is a finding."
  desc 'fix', %q(Configure the policy value for Computer Configuration >> Administrative Templates >> OneDrive >> "Allow syncing OneDrive accounts for only specific organizations", with the Tenant GUID of the organization's DoD instance in the format 1111-2222-3333-4444.

If the organization does not have an instance of OneDrive, configure the Tenant GUID with "1111-2222-3333-4444".

Group policy files for OneDrive are located on a system with OneDrive in "%localappdata%\Microsoft\OneDrive\BuildNumber\adm\".

Copy the OneDrive.admx and .adml files to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive for Business 2016'
  tag check_id: 'C-33231r603236_chk'
  tag severity: 'medium'
  tag gid: 'V-230562'
  tag rid: 'SV-230562r569322_rule'
  tag stig_id: 'DTOO605'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-33206r603118_fix'
  tag 'documentable'
  tag legacy: ['SV-98853', 'V-88203']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
