control 'SV-213429' do
  title 'Microsoft Defender AV must be configured to not exclude files for scanning.'
  desc 'This policy setting allows disabling of scheduled and real-time scanning for files under the paths specified or for the fully qualified resources specified. Paths should be added under the Options for this setting. Each entry must be listed as a name value pair where the name should be a string representation of a path or a fully qualified resource name. As an example, a path might be defined as: "c:\\Windows" to exclude all files in this directory. A fully qualified resource name might be defined as: "C:\\Windows\\App.exe". The value is not used and it is recommended that this be set to 0.

Exceptions can be made to allow file/folders that are impacting enterprise applications to be excluded from being scanned. All exclusions should be documented and approved.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Exclusions >> "Path Exclusions" is set to "Disabled" or "Not Configured.
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Exclusions
 
Criteria: If the value "Exclusions_Paths" does not exist, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Exclusions >> "Path Exclusions" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14654r820134_chk'
  tag severity: 'medium'
  tag gid: 'V-213429'
  tag rid: 'SV-213429r823030_rule'
  tag stig_id: 'WNDF-AV-000005'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14652r823029_fix'
  tag 'documentable'
  tag legacy: ['SV-89835', 'V-75155']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
