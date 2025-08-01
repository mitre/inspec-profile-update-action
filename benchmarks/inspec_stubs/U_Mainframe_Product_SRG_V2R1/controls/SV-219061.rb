control 'SV-219061' do
  title 'The Mainframe Product must provide the capability for authorized users to remotely view/hear, in real time, all content related to an established user session from a component separate from the Mainframe Product being monitored.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.

This requirement does not apply to applications that do not have a concept of a user session (e.g., calculator).'
  desc 'check', 'If the Mainframe Product has no function or capability for session operations, this is not applicable.

Examine installation and configuration settings.

If the  Mainframe Product does not have the capability to remotely view/hear, in real time, all content related to an established user session from a component separate from the Mainframe Product being monitored, this a finding.

If the Mainframe Product does not restrict this capability  to system programmers and security administrators,  this is a finding.

If an external security manager (ESM) is in use, verify that the ESM restricts the capability to remotely view/hear, in real time, all content related to an established user session from a component separate from the Mainframe Product being monitored to system programmers or security administrators. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to permit authorized users to remotely view/hear, in real time, all content related to an established user session from a component separate from the Mainframe Product being monitored.

If an ESM is in use, configure rules to restrict the ability to remotely view/hear, in real time, all content related to an established user session from a component separate from the Mainframe Product being monitored to system programmers and security administrators.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-20871r300099_chk'
  tag severity: 'medium'
  tag gid: 'V-219061'
  tag rid: 'SV-219061r865207_rule'
  tag stig_id: 'SRG-APP-000355-MFP-000139'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-20870r859697_fix'
  tag 'documentable'
  tag legacy: ['SV-82729', 'V-68239']
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
