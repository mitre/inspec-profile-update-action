control 'SV-233311' do
  title 'For endpoints that require automated remediation, Forescout must be configured to redirect endpoints to a logically separate VLAN for remediation services.'
  desc 'Automated and manual procedures for remediation for critical security updates will be managed differently. Continuing to assess and remediate endpoints with risks that could endanger the network could impact network usage for all users. This isolation prevents traffic from flowing with traffic from endpoints that have been fully assessed and authorized.

Unauthenticated devices must not be allowed to connect to remediation services.

Forescout accepts only endpoints with IP addresses that are in range. Configure Forescout to identify the endpoint. By default the IP address is used as the endpoint identifier. The system can be configured to capture the following other endpoint unique identifiers if approved for use by the SSP as the identification method: BIOS Serial number and other hardcoded attributes, OS host name, etc.'
  desc 'check', 'If automated remediation is not required by the SSP, this is not a finding.

Verify Forescout is configured to redirect endpoints requiring automated remediation to a separated VLAN that is isolated from trusted traffic.

1. From the Policy tab, select the top most policy.
2. Verify at least one endpoint policy exists that redirects failed endpoints to a VLAN that is separate from the trusted network.

If Forescout does not have one or more policies that redirect endpoints that require automated remediation to a VLAN that is isolated and logically separated, this is a finding.'
  desc 'fix', 'Configure Forescout to identify the endpoint. 

1. From the Policy tab, select the top most policy.
2. Select Add >> Classification >> Primary Classification, and then click Next.
3. Give the policy a name, then click Next.
4. Select the IP Address Range the policy will apply to, click "OK," and then click "Next". 
5. Select "Finish", and then click "Apply".

This collects a series of attributes for each endpoint that can then be used in a policy as the unique identifier. However, by default the IP address is used, for example in the log records.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36506r605636_chk'
  tag severity: 'high'
  tag gid: 'V-233311'
  tag rid: 'SV-233311r616544_rule'
  tag stig_id: 'FORE-NC-000030'
  tag gtitle: 'SRG-NET-000015-NAC-000040'
  tag fix_id: 'F-36471r616543_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
