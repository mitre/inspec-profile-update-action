control 'SV-6995' do
  title 'USB devices with persistent memory are not formatted in a manner to allow the application of Access Controls to files or data stored on the device.'
  desc 'Without using a format that allows the application of access controls to the device files stored on the USB device may be accessed from any system that the device is connected to.
Note that access controls are easily bypassed on USB devices so this should not be considered an adequate replacement for encryption.
The IAO, SA, and user will ensure that USB devices with persistent memory are formatted in a manner to allow the application of Access Controls to files or data stored on the device.'
  desc 'check', 'The reviewer will interview the IAO to verify that USB devices with persistent memory are formatted in a manner to allow the application of Access Controls to files or data stored on the device.'
  desc 'fix', 'Develop a process to disseminate the requirement that USB devices with persistent memory will be formatted in a manner to allow the application of Access Controls to files or data stored on the device.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6773'
  tag rid: 'SV-6995r1_rule'
  tag stig_id: 'USB01.008.00'
  tag gtitle: 'USB Format for Access Controls'
  tag fix_id: 'F-6426r1_fix'
  tag 'documentable'
  tag responsibility: ['Other', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'DCBP-1'
end
