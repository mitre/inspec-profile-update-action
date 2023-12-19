control 'SV-7022' do
  title 'The devices and their spoolers do not have auditing enabled.'
  desc 'Without auditing the identification and prosecution of an individual that performs malicious actions is difficult if not impossible.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that devices and their spoolers have auditing fully enabled.'
  desc 'fix', 'Configure the devices and their spoolers have auditing fully enabled.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6797'
  tag rid: 'SV-7022r1_rule'
  tag stig_id: 'MFD06.001'
  tag gtitle: 'MFD and Spooler Auditing'
  tag fix_id: 'F-6465r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
