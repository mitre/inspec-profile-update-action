control 'SV-30013' do
  title 'Automatic Call Answering to the Hardware Management Console must be disabled.'
  desc 'Automatic Call Answering to the Hardware Management Console allows unrestricted access by unauthorized personnel and could lead to a bypass of security, access to the system, and an altering of the environment. This would result in a loss of secure operations and impact the integrity of the operating environment, files, and programs. Note: Dial-in access to the Hardware Management Console is prohibited.  Also, many newer processors (e.g., zEC12/zBC12 processors) will not have modems.  If there is no modem, this check is not applicable.'
  desc 'check', 'Have the System Administrator verify if either the Enable Remote Operations parameter or the Automatic Call Answering parameter are active on the Enable Hardware Management Console Services panel.

The  Enable Remote Operations is found under Customize Remote Services and Automatic Call Answering is found under Customize Auto Answer Settings.

If either of the above options are active, then this is a FINDING.'
  desc 'fix', 'The System Administrator must set dial-in facility to off. Do this by ensuring that both the Enable Remote Operations parameter and the Automatic Call Answering parameter are turned off. 

In Check Content:  Enable Remote Operations is found under Customize Remote Services and Automatic Call Answering is found under Customize Auto Answer Settings.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24350'
  tag rid: 'SV-30013r3_rule'
  tag stig_id: 'HMC0050'
  tag gtitle: 'HMC0050'
  tag fix_id: 'F-26737r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'EBRP-1, EBRU-1'
  tag cci: ['CCI-002227', 'CCI-002235']
  tag nist: ['AC-6 (5)', 'AC-6 (10)']
end
