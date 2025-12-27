control 'SV-243427' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to not exclude any files from being scanned unless exclusions have been documented with, but also be approved by the ISSO/ISSM/AO.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring antivirus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Exclusions tab, locate the "What not to scan:" label. Ensure there are no exclusions listed. If exclusions are listed, verify they have been documented and approved by the ISSO/ISSM/AO.

Criteria: If there are no exclusions listed in the "What not to scan:" field, this is a not finding. 
If there are exclusions listed in the "What not to scan:" field, and the exclusions have been documented with, and approved by, the ISSO/ISSM/AO, this is not a finding. 
If there are exclusions listed in the "What not to scan:" field, and the exclusions have not been documented with, and approved by, the ISSO/ISSM/AO, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria: If the value NumExcludeItems is 0, this is not a finding. 
If NumExcludeItems is not 1 or greater, and exclusions have been not been documented with and approved by the ISSO/ISSM/AO, this is a finding.
If NumExcludeItems is 1 or greater, and exclusions have been approved by the ISSO/ISSM/AO, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Exclusions tab, locate the "What not to scan:" label. Remove any exclusions listed.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46702r722618_chk'
  tag severity: 'medium'
  tag gid: 'V-243427'
  tag rid: 'SV-243427r722620_rule'
  tag stig_id: 'DTAM153'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46659r722619_fix'
  tag 'documentable'
  tag legacy: ['V-42556', 'SV-55284']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
