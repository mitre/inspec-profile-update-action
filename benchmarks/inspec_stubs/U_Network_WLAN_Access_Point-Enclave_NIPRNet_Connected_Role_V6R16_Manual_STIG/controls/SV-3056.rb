control 'SV-3056' do
  title 'Group accounts must not be configured for use on the network device.'
  desc 'Group accounts configured for use on a network device do not allow for accountability or repudiation of individuals using the shared account.  If group accounts are not changed when someone leaves the group, that person could possibly gain control of the network device.  Having group accounts does not allow for proper auditing of who is accessing or changing the network.'
  desc 'check', 'Review the network device configuration and validate there are no group accounts configured for access.

If a group account is configured on the device, this is a finding.'
  desc 'fix', 'Configure individual user accounts for each authorized person then remove any group accounts.'
  impact 0.7
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3503r11_chk'
  tag severity: 'high'
  tag gid: 'V-3056'
  tag rid: 'SV-3056r7_rule'
  tag stig_id: 'NET0460'
  tag gtitle: 'Group accounts are defined.'
  tag fix_id: 'F-3081r9_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
