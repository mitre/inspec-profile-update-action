control 'SV-253475' do
  title 'User Account Control must virtualize file and registry write failures to per-user locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures non-UAC compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56928r829507_chk'
  tag severity: 'medium'
  tag gid: 'V-253475'
  tag rid: 'SV-253475r829509_rule'
  tag stig_id: 'WN11-SO-000275'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-56878r829508_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
