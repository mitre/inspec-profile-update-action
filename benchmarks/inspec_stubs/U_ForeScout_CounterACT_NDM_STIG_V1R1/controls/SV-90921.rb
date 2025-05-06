control 'SV-90921' do
  title 'CounterACT must limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If CounterACT were to enable unauthorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Ask if there are users defined in CounterACT that are not authorized to change the software libraries.

Verify that Administrator privileges have been restricted for these users.

This is verified by reviewing the administrator account profiles and auditing the assigned privilege for updated CounterACT software.

1. Log on to the CounterACT Console and select Tools >> Options >> Console User Profiles.
2. Select the non-privileged user profiles and then select "Edit".
3. Verify the users do not have the "Plugin Management" and "Software Upgrade" options selected.

If CounterACT is not configured to limit privileges to change the software resident within software libraries for unauthorized users, this is a finding.'
  desc 'fix', 'Configure CounterACT to prevent access to change the software resident within software libraries for unauthorized personnel.

1. Log on to the CounterACT Console and select Tools >> Options >> Console User Profiles.
2. Select the non-privileged user profiles and then select "Edit".
3. Verify the users do not have the "Plugin Management" and "Software Upgrade" options selected.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76233'
  tag rid: 'SV-90921r1_rule'
  tag stig_id: 'CACT-NM-000024'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-82869r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
