control 'SV-213465' do
  title 'Microsoft Defender AV must be configured for automatic remediation action to be taken for threat alert level Medium.'
  desc 'This policy setting allows the customization of which automatic remediation action will be taken for each threat alert level. Threat alert levels should be added under the Options for this setting. Each entry must be listed as a name value pair. The name defines a threat alert level. The value contains the action ID for the remediation action that should be taken. 

Valid threat alert levels are:  
1 = Low  
2 =  Medium  
4 = High  
5 = Severe  

Valid remediation action values are: 
2 = Quarantine  
3 = Remove  
6 = Ignore'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Threats >> "Specify threat alert levels at which default action should not be taken when detected" is set to "Enabled". 

Click the "Show…" box option and verify the "Value name" field contains a value of "2" and the "Value" field  contains a "2". A value of "3" in the "Value" field is more restrictive and also an acceptable value.
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction

Criteria: If the value "2" is REG_SZ = 2 (or 3), this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Threats >> "Specify threat alert levels at which default action should not be taken when detected" to "Enabled".  

Select the "Show…" option box and enter "2" in the "Value name" field and enter "2" in the "Value" field.'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14690r820242_chk'
  tag severity: 'medium'
  tag gid: 'V-213465'
  tag rid: 'SV-213465r823099_rule'
  tag stig_id: 'WNDF-AV-000041'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-14688r823098_fix'
  tag 'documentable'
  tag legacy: ['SV-94671', 'V-79967']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
