control 'SV-3455' do
  title 'Terminal Services is configured to use a common temporary folder for all sessions.'
  desc 'This setting, which is located under the Temporary Folders section of the Terminal Services configuration option, controls the use of per session temporary folders or of a communal temporary folder.  If this setting is enabled, only one temporary folder is used for all terminal services sessions.  If a communal temporary folder is used, it might be possible for users to access other users temporary folders.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Temporary Folders “Do Not Use Temp Folders per Session” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3455'
  tag rid: 'SV-3455r1_rule'
  tag gtitle: 'TS/RDS - Do Not Use Temp Folders'
  tag fix_id: 'F-5925r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECRC-1'
end
