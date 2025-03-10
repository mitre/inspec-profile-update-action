control 'SV-225523' do
  title 'User Account Control must virtualize file and registry write failures to per-user locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27222r471911_chk'
  tag severity: 'medium'
  tag gid: 'V-225523'
  tag rid: 'SV-225523r569185_rule'
  tag stig_id: 'WN12-SO-000085'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27210r471912_fix'
  tag 'documentable'
  tag legacy: ['V-14242', 'SV-52953']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
