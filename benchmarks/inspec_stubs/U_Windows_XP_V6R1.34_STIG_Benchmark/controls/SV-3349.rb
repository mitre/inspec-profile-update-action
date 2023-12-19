control 'SV-3349' do
  title 'Windows Messenger (MSN Messenger, .NET messenger) is run at system startup.'
  desc 'This setting prevents the automatic launch of Windows Messenger at user logon.  

Instant Messaging clients must be in compliance of with the Instant Messaging STIG.  Windows Messenger should not be active on Windows unless the instant messaging system is a Managed Enterprise Service for unclassified data for which the DAA has approved.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Messenger “Do Not Automatically Start Windows Messenger Initially” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3349'
  tag rid: 'SV-3349r1_rule'
  tag gtitle: 'Windows Messenger - Do Not Start Automatically'
  tag fix_id: 'F-5828r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECIM-1'
end
