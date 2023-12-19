control 'SV-6988' do
  title 'USB devices are attached to a DoD IS without prior IAO approval.'
  desc 'The IAO needs to be aware of what type of USB devices are being attached to DoD ISs and needs to stop prohibited devices from being attached.  By requiring the IAO to approve the USB devices the IAO will be informed.
The IAO or SA will ensure that no USB device is attached to a DoD IS unless approved by the IAO.'
  desc 'check', 'The reviewer will interview the IAO or SA to verify that prior approval by the IAO is required before USB devices are attached to DoD ISs and that this policy is disseminated to all users.'
  desc 'fix', 'The IAO will know that approval by the IAO is required before USB devices are attached to DoD ISs and the IAO will ensure that this policy is disseminated to all users.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6766'
  tag rid: 'SV-6988r1_rule'
  tag stig_id: 'USB01.002.00'
  tag gtitle: 'USB Devices Without Prior Approval'
  tag fix_id: 'F-6419r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'DCBP-1'
end
