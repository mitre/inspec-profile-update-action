control 'SV-213434' do
  title 'Windows Defender AV must be configured to join Microsoft MAPS.'
  desc 'This policy setting allows you to join Microsoft MAPS. Microsoft MAPS is the online community that helps you choose how to respond to potential threats. The community also helps stop the spread of new malicious software infections. You can choose to send basic or additional information about detected software. Additional information helps Microsoft create new definitions and help it to protect your computer. This information can include things like location of detected items on your computer if harmful software was removed. The information will be automatically collected and sent. In some instances personal information might unintentionally be sent to Microsoft. However Microsoft will not use this information to identify you or contact you. Possible options are: (0x0) Disabled (default) (0x1) Basic membership (0x2) Advanced membership Basic membership will send basic information to Microsoft about software that has been detected including where the software came from the actions that you apply or that are applied automatically and whether the actions were successful. Advanced membership in addition to basic information will send more information to Microsoft about malicious software spyware and potentially unwanted software including the location of the software file names how the software operates and how it has impacted your computer. If you enable this setting you will join Microsoft MAPS with the membership specified. If you disable or do not configure this setting you will not join Microsoft MAPS. In Windows 10 Basic membership is no longer available so setting the value to 1 or 2 enrolls the device into Advanced membership.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> MAPS >> "Join Microsoft MAPS" is set to "Enabled" and "Advanced MAPS" selected from the drop down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet

Criteria: If the value "SpynetReporting" is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'This is applicable to unclassified systems, for other systems this is NA.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> MAPS >> "Join Microsoft MAPS" to "Enabled" and select "Advanced MAPS" from the drop down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14659r531367_chk'
  tag severity: 'medium'
  tag gid: 'V-213434'
  tag rid: 'SV-213434r569189_rule'
  tag stig_id: 'WNDF-AV-000010'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14657r531368_fix'
  tag 'documentable'
  tag legacy: ['SV-89847', 'V-75167']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
