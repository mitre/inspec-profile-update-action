control 'SV-80433' do
  title 'Trend Deep Security must configure malicious code protection mechanisms to perform periodic scans of the information system every seven (7) days.'
  desc 'Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, Trojan horses, and Spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure malicious code protection mechanisms perform periodic scans of the information system every seven (7) days.

Analyze one of the custom policies under the “Policies” tab, by right clicking and selecting “Details.”
Verify the following settings are enabled:

1. Under the Overview >> General tab, "Anti-Malware" is set to “On”
2. Under the Anti-Malware >> General tab, “Real-Time Scan” is set to “Default”
3. Under the Anti-Malware >> General tab, a custom “Malware Scan Configuration” is enabled with a Schedule configured to no more than 7 days.

If "Anti-Malware" is set anything other than “On” this is a finding. 

If “Malware Scan Configuration” is set to “No Configuration,” this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server malicious code protection mechanisms to perform periodic scans of the information system every seven (7) days.

To enable malicious code protection via the anti-malware, configure the following settings under the “Policies” tab.
Under “Policies” right clicking and selecting “Details.” Configure the following settings:

1. Under the Overview >> General tab, set "Anti-Malware" to “On”
2. Under the Anti-Malware >> General tab, set “Real-Time Scan” to “Default”
3. Under the Anti-Malware >> General tab, set a weekly scan under “Scheduled” by selecting “New”. Name the scheduled scan “Weekly” and configure it for a select day and time of the week. Click “OK” when finished.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66591r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65943'
  tag rid: 'SV-80433r1_rule'
  tag stig_id: 'TMDS-00-000210'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-72019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
