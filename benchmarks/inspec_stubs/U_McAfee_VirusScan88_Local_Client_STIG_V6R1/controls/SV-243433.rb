control 'SV-243433' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to not exclude any script URLs from being scanned unless the URL exclusions have been documented with, and approved by the ISSO/ISSM/DAA.'
  desc 'Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. All scripts should be scanned and none should be excluded from scanning.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the ScriptScan tab, locate the "ScriptScan URL exclusions:" label. Ensure there are no URL exclusions listed in the URL field.

Criteria:  If there are no exclusions listed in the URL field, this is a not finding. 
If there are exclusions listed in the URL field, and the exclusions have been documented with, and approved by, the ISSO/ISSM/DAA, this is not a finding. 
If there are exclusions listed in the URL field, and the exclusions have not been documented with, and approved by, the ISSO/ISSM/DAA, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Script Scanner

Criteria:  If the ExcludedURLs REG_MULTI_SZ has any entries, and the excluded URLs have not been documented with, and approved by, the ISSO/ISSM/DAA, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the ScriptScan tab, locate the "ScriptScan exclusions" label. Ensure there are no exclusions listed in the URL field.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46708r722636_chk'
  tag severity: 'medium'
  tag gid: 'V-243433'
  tag rid: 'SV-243433r722638_rule'
  tag stig_id: 'DTAM160'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46665r722637_fix'
  tag 'documentable'
  tag legacy: ['V-42573', 'SV-55301']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
