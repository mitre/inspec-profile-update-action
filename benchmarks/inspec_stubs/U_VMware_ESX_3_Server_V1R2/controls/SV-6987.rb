control 'SV-6987' do
  title 'MP3 players, camcorders, or digital cameras are being attached to ISs without prior DAA approval.'
  desc 'These devices contain non-volatile memory and could be used to infect an IS to which they are attached with malicious code or they could be used to transport sensitive data leading to the compromise of the data.  Finally there is normally no DoD requirement for these devices to be attached to a DoD asset.
The IAO, SA, and user will ensure that MP3 players, camcorders, or digital cameras are not attached to ISs without prior DAA approval.'
  desc 'check', 'The reviewer will interview the IAO to verify that the IAO knows that USB devices such as MP3 players, camcorders, or digital cameras are not to be attached to ISs without prior DAA approval, and that this information is disseminated to all users.'
  desc 'fix', 'The IAO will be made aware of the policy that USB devices such as MP3 players, camcorders, or digital cameras are not to be attached to ISs without prior DAA approval.  The IAO will disseminate the policy to all users.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2912r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6765'
  tag rid: 'SV-6987r1_rule'
  tag stig_id: 'USB01.001.00'
  tag gtitle: 'USB MP3 Players Camcorders and digital cameras'
  tag fix_id: 'F-6418r1_fix'
  tag 'documentable'
  tag responsibility: ['Other', 'Information Assurance Officer', 'System Administrator']
end
