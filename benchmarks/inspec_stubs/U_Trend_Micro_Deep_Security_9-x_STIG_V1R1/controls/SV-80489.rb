control 'SV-80489' do
  title 'Trend Deep Security must continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.'
  desc 'Evidence of malicious code is used to identify potentially compromised information systems or information system components. Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. 

This requirement applies to applications that provide monitoring capability for unusual/unauthorized activities including, but are not limited to, host-based intrusion detection, anti-virus, and malware applications.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure inbound communications traffic is continuously monitored for unusual or unauthorized activities or conditions.

Verify the state of the Intrusion Prevent policies:

- Select “Computers” on the top menu bar
- Choose the appropriate group and within the main page and select a computer for review.
- Double click the selected computer and click “Intrusion Prevention”
- Verify the following settings are enabled:
  - Configuration: is set to Inherit or On
  - “State:” is listing “Activated”
  - Policies are defined under the Assigned Intrusion Prevention Rules. 

If any of these settings are not configured, this is a finding'
  desc 'fix', 'Configure the Trend Deep Security server to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.

To enable Intrusion Prevent within Deep Security, go to “Computers”, on the top menu bar.
  
- Choose the appropriate group and within the main page and select a computer for review.
- Double click the selected computer and click Intrusion Prevention. 
- Enable the following settings:
  - Configuration: Set to Inherit or On (according to local security policies) 
  - Verify “State:” is listing “Activated”
  - Assign the appropriate policies under the Assigned Intrusion Prevention Rules.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65999'
  tag rid: 'SV-80489r1_rule'
  tag stig_id: 'TMDS-00-000340'
  tag gtitle: 'SRG-APP-000469'
  tag fix_id: 'F-72075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
