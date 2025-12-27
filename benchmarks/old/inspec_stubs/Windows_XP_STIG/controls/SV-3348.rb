control 'SV-3348' do
  title 'The user is allowed to launch Windows Messenger (MSN Messenger, .NET Messenger).'
  desc 'This setting prevents the Windows Messenger client from being run.  

Instant Messaging clients must be in compliance of with the Instant Messaging STIG.  Windows Messenger should not be active on Windows unless the instant messaging system is a Managed Enterprise Service for unclassified data for which the DAA has approved.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Messenger “Do Not Allow Windows Messenger to be Run” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3348'
  tag rid: 'SV-3348r1_rule'
  tag gtitle: 'Windows Messenger - Do Not Allow To Run'
  tag fix_id: 'F-5827r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECIM-1'
end
