control 'SV-213453' do
  title 'Microsoft Defender AV virus definition age must not exceed 7 days.'
  desc 'This policy setting allows defining the number of days that must pass before virus definitions are considered out of date. If definitions are determined to be out of date, this state may trigger several additional actions, including falling back to an alternative update source or displaying a warning icon in the user interface. By default, this value is set to 14 days. 

If this setting is enabled, virus definitions will be considered out of date after the number of days specified have passed without an update. If this setting is disabled or not configured, virus definitions will be considered out of date after the default number of days have passed without an update.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >>Security Intelligence Updates >> "Define the number of days before virus security intelligence considered out of date" is set to "Enabled" and "7" or less is selected in the drop-down box (excluding "0", which is unacceptable).

If third-party antivirus protection is installed and up to date, the Windows Defender Antivirus age requirement is NA.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates

Criteria: If the value "AVSignatureDue" is REG_DWORD = 7, this is not a finding.

A value of 1 - 6 is also acceptable and not a finding.

A value of 0 is a finding.

A value higher than 7 is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Signature Updates >> "Define the number of days before virus definitions are considered out of date" to "Enabled" and select "7" or less in the drop-down box.

Do not select a value of 0. This disables the option.'
  impact 0.7
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14678r820206_chk'
  tag severity: 'high'
  tag gid: 'V-213453'
  tag rid: 'SV-213453r823075_rule'
  tag stig_id: 'WNDF-AV-000029'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-14676r823074_fix'
  tag 'documentable'
  tag legacy: ['SV-89923', 'V-75243']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
