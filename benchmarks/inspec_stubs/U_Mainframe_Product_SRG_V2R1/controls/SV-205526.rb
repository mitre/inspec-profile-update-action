control 'SV-205526' do
  title 'The Mainframe Product must automatically update malicious code protection mechanisms.'
  desc 'Malicious software detection applications need to be constantly updated in order to identify new threats as they are discovered. 

All malicious software detection software must come with an update mechanism that automatically updates the application and any associated signature definitions. The organization (including any contractor to the organization) is required to promptly install security-relevant malicious code protection software updates. Examples of relevant updates include anti-virus signatures, detection heuristic rule sets, and/or file reputation data employed to identify and/or block malicious software from executing.

Malicious code includes viruses, worms, Trojan horses, and Spyware. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'If the Mainframe Product has no function or capability for providing malicious code scanning or protection, this is not applicable.

Refer to organizational-defined update procedures.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to receive automatic updates using organizational-defined procedures, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to receive automatic updates using organizational-defined procedures.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5792r299811_chk'
  tag severity: 'medium'
  tag gid: 'V-205526'
  tag rid: 'SV-205526r397855_rule'
  tag stig_id: 'SRG-APP-000272-MFP-000347'
  tag gtitle: 'SRG-APP-000272'
  tag fix_id: 'F-5792r299812_fix'
  tag 'documentable'
  tag legacy: ['SV-82977', 'V-68487']
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
