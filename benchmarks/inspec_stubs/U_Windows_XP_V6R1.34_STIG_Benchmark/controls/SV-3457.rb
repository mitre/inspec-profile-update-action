control 'SV-3457' do
  title 'Terminal Services is not configured to set a time limit for disconnected sessions.'
  desc 'This setting controls how long a session will remain open if it is unexpectedly terminated.  Such sessions should be terminated as soon as possible.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Sessions “Set Time Limit for Disconnected Sessions” to “Enabled”, and the “End a disconnected session” to “1 minute".'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3457'
  tag rid: 'SV-3457r1_rule'
  tag gtitle: 'TS/RDS - Time Limit for Disc. Session'
  tag fix_id: 'F-34274r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
