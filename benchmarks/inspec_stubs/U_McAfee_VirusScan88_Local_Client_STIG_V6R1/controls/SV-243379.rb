control 'SV-243379' do
  title 'McAfee VirusScan On-Demand scan must be configured so there are no exclusions from the scan unless exclusions have been documented with, and approved by, the ISSO/ISSM/DAA.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring antivirus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Exclusions tab, locate the "What not to scan:" label. Ensure that no items are listed in this area. If any items are listed, they must be documented with, and approved by, the local ISSO/ISSM/DAA.

Criteria:  If no items are listed in the "What not to scan:" area, this is not a finding.
If excluded items exist, and they are documented with and approved by the ISSO/ISSM/DAA, this is not a finding.
If excluded items exist, and they are not documented with and approved by the ISSO/ISSM/DAA, this is a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the NumExcludeItems has value of 0, this is not a finding.
If the NumExcludeItems has value other than 0, and they are documented with and approved by the ISSO/ISSM/DAA, this is not a finding.
If the NumExcludeItems has value other than 0, and they are not documented with and approved by the ISSO/ISSM/DAA, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click on the Task and select Properties.

Under the Exclusions tab, locate the "What not to scan:" label, remove any items.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46654r722474_chk'
  tag severity: 'medium'
  tag gid: 'V-243379'
  tag rid: 'SV-243379r722476_rule'
  tag stig_id: 'DTAM050'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46611r722475_fix'
  tag 'documentable'
  tag legacy: ['V-6620', 'SV-56425']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
