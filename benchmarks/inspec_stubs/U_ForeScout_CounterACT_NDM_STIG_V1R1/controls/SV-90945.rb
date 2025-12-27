control 'SV-90945' do
  title 'CounterACT must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The administrator must acknowledge the banner prior to CounterACT allowing the administrator access to CounterACT. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement.

In the case of CLI access using a terminal client, entering the username and password when the banner is presented is considered an explicit action of acknowledgement. Entering the username, viewing the banner, and then entering the password is also acceptable.'
  desc 'check', 'Verify CounterACT retains the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and takes explicit actions to log on for further access.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the options for the logon banner "require confirmation" is selected.

If CounterACT does not retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'Configure CounterACT to retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the options for logon banner "require confirmation" is selected.'
  impact 0.3
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75943r1_chk'
  tag severity: 'low'
  tag gid: 'V-76257'
  tag rid: 'SV-90945r1_rule'
  tag stig_id: 'CACT-NM-000022'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-82893r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
