control 'SV-253285' do
  title 'The Windows PowerShell 2.0 feature must be disabled on the system.'
  desc 'Windows PowerShell 5.0 added advanced logging features which can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.'
  desc 'check', 'Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter the following:
Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2*

If either of the following have a "State" of "Enabled", this is a finding.

FeatureName : MicrosoftWindowsPowerShellV2
State : Enabled
FeatureName : MicrosoftWindowsPowerShellV2Root
State : Enabled

Alternately:
Search for "Features".

Select "Turn Windows features on or off".

If "Windows PowerShell 2.0" (whether the subcategory of "Windows PowerShell 2.0 Engine" is selected or not) is selected, this is a finding.'
  desc 'fix', 'Disable "Windows PowerShell 2.0" on the system.

Run "Windows PowerShell" with elevated privileges (run as administrator).
Enter the following:
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

This command must disable both "MicrosoftWindowsPowerShellV2Root" and "MicrosoftWindowsPowerShellV2" which correspond to "Windows PowerShell 2.0" and "Windows PowerShell 2.0 Engine" respectively in "Turn Windows features on or off".

Alternately:
Search for "Features".
Select "Turn Windows features on or off".
De-select "Windows PowerShell 2.0".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56738r828937_chk'
  tag severity: 'medium'
  tag gid: 'V-253285'
  tag rid: 'SV-253285r828939_rule'
  tag stig_id: 'WN11-00-000155'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56688r828938_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
