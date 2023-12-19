control 'SV-55259' do
  title 'McAfee VirusScan On-Access Default Processes Policies must be configured to not exclude any files from being scanned unless exclusions have been documented with, and approved by, the ISSO/ISSM/DAA.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring antivirus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Note: Exclusions must be documented and approved by the ISSO, ISSM, and/or AO. 
If the site has both an ISSO and an ISSM, the exclusions must be documented by the ISSO and approved by the ISSM or as determined by internal approval structure in the organization. 
If only an ISSO or ISSM is at site, they will be responsible for both documenting and approving. 
If neither an ISSO nor ISSM is at the site, the approval falls to the AO.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. 
From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. 
Under the Exclusions tab, locate the "What not to scan:" label. Ensure there are no exclusions listed. 
If exclusions are listed, verify they have been documented and approved by the ISSO/ISSM/AO.

Criteria: If there are no exclusions listed in the "What not to scan:" field, this is a not finding. 
If there are exclusions listed in the "What not to scan:" field, and the exclusions have been documented with, and approved by, the ISSO/ISSM/AO, this is not a finding. 
If there are exclusions listed in the "What not to scan:" field, and the exclusions have not been documented with, and approved by, the ISSO/ISSM/AO, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria: If the value NumExcludeItems is 0, this is not a finding. 
If NumExcludeItems is not 1 or greater, and exclusions have not been documented with and approved by the ISSO/ISSM/AO, this is a finding.
If NumExcludeItems is 1 or greater, and exclusions have been approved by the ISSO/ISSM/AO, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Exclusions tab, locate the "What not to scan:" label. Remove any exclusions listed.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48849r7_chk'
  tag severity: 'medium'
  tag gid: 'V-42531'
  tag rid: 'SV-55259r5_rule'
  tag stig_id: 'DTAM153'
  tag gtitle: 'DTAM153--McAfee VirusScan on-access file exclusions'
  tag fix_id: 'F-48113r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
