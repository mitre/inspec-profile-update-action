control 'SV-213464' do
  title 'Microsoft Defender AV must be configured for automatic remediation action to be taken for threat alert level High.'
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

Click the "Show…" box option and verify the "Value name" field contains a value of "4" and the "Value" field  contains a "2". A value of "3" in the "Value" field is more restrictive and also an acceptable value.
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction

Criteria: If the value "4" is REG_SZ = 2 (or 3), this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Threats >> "Specify threat alert levels at which default action should not be taken when detected" to "Enabled". 

Select the "Show…" option box and enter "4" in the "Value name" field and enter "2" in the "Value" field.'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14689r820239_chk'
  tag severity: 'medium'
  tag gid: 'V-213464'
  tag rid: 'SV-213464r823097_rule'
  tag stig_id: 'WNDF-AV-000040'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-14687r823096_fix'
  tag 'documentable'
  tag legacy: ['SV-94669', 'V-79965']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
