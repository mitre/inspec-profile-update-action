control 'SV-7031' do
  title 'The device is not configured to prevent non-printer administrators from altering the global configuration of the device.'
  desc 'If unauthorized users can alter the global configuration of the MFD they can remove all security.  This can lead to the compromise of sensitive data or the compromise of the network the MFD is attached to.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that the device is configured to prevent non-printer administrators from altering the global configuration of the device.'
  desc 'fix', 'Configured the device to prevent non-printer administrators from altering the global configuration of the device.  If the device cannot be configured in this manner, replace the device with one that can be configured in an acceptable manner.'
  impact 0.7
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3021r1_chk'
  tag severity: 'high'
  tag gid: 'V-6806'
  tag rid: 'SV-7031r1_rule'
  tag stig_id: 'MFD08.002'
  tag gtitle: 'MFD/Printer Global Configuration Settings'
  tag fix_id: 'F-6480r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
