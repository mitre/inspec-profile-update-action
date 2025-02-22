control 'SV-55291' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to not exclude any script processes from being scanned unless the process exclusions have been documented with, and approved by, the ISSO/ISSM/DAA.'
  desc 'Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. All scripts should be scanned and none should be excluded from scanning.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the ScriptScan tab, locate the "ScriptScan process exclusions:" label. Ensure there are no exclusions listed in the Process field.

Criteria:  If there are no exclusions listed in the Process field, this is a not finding. 
If there are exclusions listed in the Process field, and the exclusions have been documented with, and approved by, the ISSO/ISSM/DAA, this is not a finding. 
If there are exclusions listed in the Process field, and the exclusions have not been documented with, and approved by, the ISSO/ISSM/DAA, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Script Scanner

Criteria:  If the ExcludedProcesses REG_MULTI_SZ has any entries, and the excluded processes have not been documented with, and approved by, the ISSO/ISSM/DAA, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the ScriptScan tab, locate the "ScriptScan process exclusions" label. Remove any exclusions listed in the Process field.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49363r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42563'
  tag rid: 'SV-55291r2_rule'
  tag stig_id: 'DTAM152'
  tag gtitle: 'DTAM152--McAfee VirusScan on-access script exclusions'
  tag fix_id: 'F-48145r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
