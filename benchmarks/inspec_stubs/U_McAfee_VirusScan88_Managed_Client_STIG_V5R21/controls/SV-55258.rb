control 'SV-55258' do
  title 'McAfee VirusScan On-Access General Policies must be configured to not exclude any script processes from being scanned unless the process exclusions have been documented with, and approved by, the ISSO/ISSM/DAA.'
  desc 'Many attackers use toolkits containing several different types of utilities and scripts that can be used to probe and attack hosts. Scripts are a common carrier of malware and none should be excluded from scanning. In the unlikely event that excluding scanning a script impacts the operational function and/or availability of a system, and reasonable mitigation efforts have been put into place, the exclusion may be put into place but must be documented with, and approved by, the ISSO/ISSM/DAA.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the ScriptScan tab, locate the "ScriptScan exclusions:" label. Ensure there are no exclusions listed in the Process field.

Criteria:  If there are no exclusions listed in the Process field, this is a not finding. 
If there are exclusions listed in the Process field, and the exclusions have been documented with, and approved by, the ISSO/ISSM/DAA, this is not a finding. 
If there are exclusions listed in the Process field, and the exclusions have not been documented with, and approved by, the ISSO/ISSM/DAA, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Script Scanner

Criteria:  If the ExcludedProcesses REG_MULTI_SZ has any entries, and the excluded processes have not been documented with, and approved by, the ISSO/ISSM/DAA, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the ScriptScan tab, locate the "ScriptScan exclusions" label. Remove any exclusions listed in the Process field.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48848r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42530'
  tag rid: 'SV-55258r2_rule'
  tag stig_id: 'DTAM152'
  tag gtitle: 'DTAM152--McAfee VirusScan on-access script exclusions'
  tag fix_id: 'F-48112r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
