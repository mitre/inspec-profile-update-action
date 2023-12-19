control 'SV-233312' do
  title 'If a device requesting access fails Forescout policy assessment, Forescout must communicate with other components and the switch to either terminate the session or isolate the device from the trusted network for remediation. This is required for compliance with C2C Step 3.'
  desc 'Endpoints with identified security flaws and weaknesses endanger the network and other devices on it. Isolation or termination prevents traffic from flowing with traffic from endpoints that have been fully assessed and authorized.'
  desc 'check', 'If DoD is not at C2C Step 3 or higher, this is not a finding.

Use the Forescout Administrator UI to verify that policies are configured to filter the policy assessment devices based on risk and are remediated or isolated according to the SSP.

1. In the Forescout UI, go to the Policy Tab >> Compliance Policies.
2. Verify the action within the Compliance Policies is configured with one of the following actions:
   - Terminate the connection and place the device on a blacklist to prevent future connection attempts until action is taken to remove the device from the blacklist.
   - Redirect traffic from the remote endpoint to the automated remediation subnet for connection to the remediation server.
   - Allow the device access to limited network services such as public web servers in the protected DMZ (must be approved by the AO).
   - Allow the device and user full entry into the protected networks but flag it for future remediation. With this option, an automated reminder should be used to inform the user of the remediation status.

If Forescout does not communicate with the remote access gateway to implement a policy to either terminate the session or isolate the device from the trusted network this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure policies according to the SSP to filter assessed devices based on risk. Ensure the policies remediate or segment the at-risk devices according to the SSP.

1. In the Forescout UI, go to the Policy Tab >> Compliance Policies.
2. Select a policy, then click Edit.
3. Configure the Compliance Policies to include any of the following actions:
   - Terminate the connection and place the device on a blacklist to prevent future connection attempts until action is taken to remove the device from the blacklist.
   - Redirect traffic from the remote endpoint to the automated remediation subnet for connection to the remediation server.
   - Allow the device access to limited network services such as public web servers in the protected DMZ (must be approved by the AO).
   - Allow the device and user full entry into the protected networks but flag it for future remediation. With this option, an automated reminder must be used to inform the user of the remediation status.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36507r811372_chk'
  tag severity: 'high'
  tag gid: 'V-233312'
  tag rid: 'SV-233312r811373_rule'
  tag stig_id: 'FORE-NC-000040'
  tag gtitle: 'SRG-NET-000015-NAC-000060'
  tag fix_id: 'F-36472r803456_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
