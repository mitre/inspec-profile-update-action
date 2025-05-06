control 'SV-6993' do
  title 'Persistent memory USB devices are not labeled in accordance with the classification level of the data they contain.'
  desc 'If the persistent memory USB device is not labeled with the appropriate classification level this can lead to the compromise of sensitive data or the compromise of an IS that the device is attached.'
  desc 'check', 'The reviewer will interview the IAO or SA to verify that the labeling of persistent memory USB devices is in accordance with the classification level of the data they contain.'
  desc 'fix', 'Label persistent memory USB devices in accordance with the classification level of the data they contain.  Disseminate this policy to all users.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6771'
  tag rid: 'SV-6993r1_rule'
  tag stig_id: 'USB01.006.00'
  tag gtitle: 'Persistent Memory USB Devices Labeled'
  tag fix_id: 'F-6424r1_fix'
  tag 'documentable'
  tag responsibility: ['Other', 'Information Assurance Officer', 'System Administrator']
end
