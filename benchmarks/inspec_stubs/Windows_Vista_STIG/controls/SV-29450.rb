control 'SV-29450' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc 'Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Turn off downloading of enclosures" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15682'
  tag rid: 'SV-29450r2_rule'
  tag gtitle: 'RSS Attachment Downloads'
  tag fix_id: 'F-62315r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
