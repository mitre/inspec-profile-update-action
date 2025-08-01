control 'SV-3458' do
  title 'Terminal Services idle session time limit does not meet the requirement.'
  desc 'This setting controls how long a session may be idle before it is automatically disconnected from the server.  Users should disconnect if they plan on being away from their terminals for extended periods of time.  Idle sessions should be disconnected after 15 minutes.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Sessions “Set time limit for active but idle Terminal Services sessions” to “Enabled”, and the “Idle session limit” to 15 minutes or less, excluding 0 which equates to “Never”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3458'
  tag rid: 'SV-3458r1_rule'
  tag gtitle: 'TS/RDS - Time Limit for Idle Session'
  tag fix_id: 'F-34276r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
