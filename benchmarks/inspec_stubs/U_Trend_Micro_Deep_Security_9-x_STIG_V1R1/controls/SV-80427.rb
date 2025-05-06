control 'SV-80427' do
  title 'Trend Deep Security must automatically update malicious code protection mechanisms.'
  desc 'Malicious software detection applications need to be constantly updated in order to identify new threats as they are discovered. 

All malicious software detection software must come with an update mechanism that automatically updates the application and any associated signature definitions. The organization (including any contractor to the organization) is required to promptly install security-relevant malicious code protection software updates. Examples of relevant updates include anti-virus signatures, detection heuristic rule sets, and/or file reputation data employed to identify and/or block malicious software from executing.

Malicious code includes viruses, worms, Trojan horses, and Spyware. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure malicious code protection mechanisms are automatically updated.

Analyze the system using the Administration >> System Settings >> Updates page.

Verify that the “Automatically download updates to imported software” option is checked.

If this option is not enabled, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to automatically update malicious code protection mechanisms.

Go to the Administration >> System Settings >> Updates page, and scroll down to Software Updates.

Check the box to enable “Automatically download updates to imported software”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65937'
  tag rid: 'SV-80427r1_rule'
  tag stig_id: 'TMDS-00-000195'
  tag gtitle: 'SRG-APP-000272'
  tag fix_id: 'F-72013r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
