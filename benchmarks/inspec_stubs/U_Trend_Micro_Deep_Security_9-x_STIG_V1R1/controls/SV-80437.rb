control 'SV-80437' do
  title 'Trend Deep Security must be configured to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.'
  desc 'Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Applications providing this capability must be able to perform actions in response to detected malware. Responses include blocking, quarantining, deleting, and alerting. Other technology- or organization-specific responses may also be employed to satisfy this requirement.

Malicious code includes viruses, worms, Trojan horses, and Spyware. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure malicious code is blocked and quarantined upon detection, then send an immediate alert to appropriate individuals.

Verify the “Custom remediation actions” for “Recognized Malware” under the Policy settings for Anti-Malware.
- Under “Policies” tab right click any of the selected policies and click “Details.”
- Choose “Anti-Malware” and deselect “Default Real-Time Scan Configuration.”  Be sure to re-enable this option once the review is complete.
- Click “Edit” and select “Actions.”
- Under the “Recognized Malware” verify the following settings:
  - For Virus: Clean
  - For Trojans: Quarantine
  - For Packer: Quarantine
  - For Spyware: Quarantine
  - For Other Threats: Clean
- Under “Possible Malware” verify “Quarantine” is selected.

If any of the settings are not configured accordingly, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.

Configure the “Custom remediation actions” for “Recognized Malware” under the Policy settings for Anti-Malware.
- Under “Policies” tab right click any of the selected policies and click “Details.” 
- Choose “Anti-Malware” and deselect “Default Real-Time Scan Configuration.”  Be sure to re-enable this option once the review is complete. 
- Click “Edit” and select “Actions.”
- Under the “Recognized Malware” configure the following settings:
  - For Virus: Clean
  - For Trojans: Quarantine
  - For Packer: Quarantine
  - For Spyware: Quarantine
  - For Other Threats: Clean
- Under “Possible Malware” select “Quarantine.”'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65947'
  tag rid: 'SV-80437r1_rule'
  tag stig_id: 'TMDS-00-000220'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-72023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
