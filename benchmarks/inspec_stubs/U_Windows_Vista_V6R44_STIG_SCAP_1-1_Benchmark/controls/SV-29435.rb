control 'SV-29435' do
  title 'Event Viewer Events.asp Links'
  desc 'This check verifies that Events.asp hyperlinks in Event Viewer are available.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Event Viewer “Events.asp” links” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15672'
  tag rid: 'SV-29435r1_rule'
  tag gtitle: 'Event Viewer Events.asp Links'
  tag fix_id: 'F-15539r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
