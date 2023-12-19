control 'SV-206843' do
  title 'The Voice Video Session Manager must off-load session (call) records onto a different system or storage media.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited session record storage capacity.'
  desc 'check', 'Verify the Voice Video Session Manager off-loads session records onto a different system or storage media.

If the Voice Video Session Manager does not off-load session records onto a different system or storage media, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to off-load session records onto a different system or storage media.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7098r364718_chk'
  tag severity: 'medium'
  tag gid: 'V-206843'
  tag rid: 'SV-206843r508661_rule'
  tag stig_id: 'SRG-NET-000334-VVSM-00039'
  tag gtitle: 'SRG-NET-000334'
  tag fix_id: 'F-7098r364719_fix'
  tag 'documentable'
  tag legacy: ['SV-76611', 'V-62121']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
