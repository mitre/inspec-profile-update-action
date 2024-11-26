control 'SV-74519' do
  title 'The BIG-IP ASM module must continuously monitor inbound communications traffic crossing internal security boundaries for unusual or unauthorized activities or conditions.'
  desc 'If inbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

Internal monitoring includes the observation of events occurring on the network crossing internal boundaries at managed interfaces such as web content filters. Depending on the type of ALG, organizations can monitor information systems by monitoring audit activities, application access patterns, characteristics of access, content filtering, or unauthorized exporting of information across boundaries. Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.'
  desc 'check', 'If the BIG-IP ASM module is not used to support content filtering as part of the traffic management functions of the BIG-IP Core, this is not applicable.

Verify the BIG-IP ASM module is configured to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify the configuration for ASM Event Logging.

Navigate to the Security >> Policies tab.

Set "Policy Settings" to "Advanced".

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy for the virtual server.

Verify that "Log Profile" is Enabled and a logging profile is assigned under "Selected".

Navigate to the BIG-IP System manager >> Security >> Event Logs >> Logging Profiles.

Select the Logging Profile that was assigned to the virtual server.

Verify "Request Type" is set to "Illegal requests, and requests that include staged attack signatures" is selected under "Storage Filter".

If the BIG-IP ASM module is not configured to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'Configure a policy in the BIG-IP ASM module to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.

Apply the ASM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to continuously monitor inbound communications traffic for unusual or unauthorized activities or conditions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60089'
  tag rid: 'SV-74519r1_rule'
  tag stig_id: 'F5BI-AS-000239'
  tag gtitle: 'SRG-NET-000390-ALG-000139'
  tag fix_id: 'F-65583r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
