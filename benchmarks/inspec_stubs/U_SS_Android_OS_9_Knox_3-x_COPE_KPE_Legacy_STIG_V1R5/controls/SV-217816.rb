control 'SV-217816' do
  title 'Samsung Android must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review device configuration settings to confirm that USB mass storage mode has been disabled. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "disable USB media player" is selected. 

Connect the Samsung Android device to a non-DoD network-managed PC with a USB cable. 

On the PC, browse the mounted Samsung Android device and verify that it does not display any folders or files. 

If on the MDM console "disable USB media player" is not selected, or the PC can mount and browse folders and files on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable USB mass storage mode. 

On the MDM console, for the device, in the "Knox restrictions" group, select "disable USB media player".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19032r362906_chk'
  tag severity: 'medium'
  tag gid: 'V-217816'
  tag rid: 'SV-217816r617456_rule'
  tag stig_id: 'KNOX-09-000685'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-19030r362907_fix'
  tag 'documentable'
  tag legacy: ['SV-103979', 'V-93893']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
