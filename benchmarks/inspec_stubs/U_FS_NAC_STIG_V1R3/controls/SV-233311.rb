control 'SV-233311' do
  title 'For endpoints that require automated remediation, Forescout must be configured to redirect endpoints to a logically separate network segment for remediation services. This is required for compliance with C2C Step 4.'
  desc 'Automated and manual procedures for remediation for critical security updates will be managed differently. Continuing to assess and remediate endpoints with risks that could endanger the network could impact network usage for all users. This isolation prevents traffic from flowing with traffic from endpoints that have been fully assessed and authorized.

Unauthenticated devices must not be allowed to connect to remediation services.

Forescout accepts only endpoints with IP addresses that are in range. Configure Forescout to identify the endpoint. By default the IP address is used as the endpoint identifier. The system can be configured to capture the following other endpoint unique identifiers if approved for use by the SSP as the identification method: BIOS Serial number and other hardcoded attributes, OS host name, etc.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.
If automated remediation is not required by the SSP, this is not a finding.

Use the Forescout Administrator UI to verify that Forescout is configured to redirect endpoints requiring automated remediation to a network segment that is isolated from trusted traffic.

If Forescout does not have one or more policies that redirect endpoints that require automated remediation to a logically isolated, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure a policy, per the SSP, that isolates endpoints requiring automated remediation from other endpoints on the trusted network. The following is an example only.

1. From the Policy tab, select the top most policy.
2. Select Add >> Classification >> Primary Classification, and then click Next.
3. Give the policy a name, then click Next.
4. Select the IP Address Range the policy will apply to, click "OK," and then click "Next". 
5. Select "Finish", and then click "Apply".

This collects a series of attributes for each endpoint that can then be used in a policy as the unique identifier. However, by default the IP address is used, for example in the log records.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36506r811370_chk'
  tag severity: 'high'
  tag gid: 'V-233311'
  tag rid: 'SV-233311r811371_rule'
  tag stig_id: 'FORE-NC-000030'
  tag gtitle: 'SRG-NET-000015-NAC-000040'
  tag fix_id: 'F-36471r803453_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
