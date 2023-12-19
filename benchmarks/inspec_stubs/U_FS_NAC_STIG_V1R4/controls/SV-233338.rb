control 'SV-233338' do
  title 'Forescout must deny network connection for endpoints that cannot be authenticated using an approved method. This is required for compliance with C2C Step 4.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Identification failure does not need to result in connection termination or preclude compliance assessment. This is particularly true for unmanaged systems or when the NAC is performing network discovery.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Use the Forescout Administrator UI to verify that a policy exists to deny network connections for endpoints that cannot be authenticated using an approved method and that the authentication failure is logged.

1. Log on to Forescout UI.
2. From the Policy tab, select the Authentication and Authorization policy.
3. Find the 802.1x Authorization policy.

If NAC does not have an authorization policy that denies network connection for endpoints that cannot be authenticated using an approved method and log authentication failures, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure a policy to deny network access using a control action for any endpoints that cannot be authenticated using an approved method as defined in the SSP.

1. Log on to Forescout UI.
2. From the Policy tab, select the Authentication and Authorization policy.
3. Find the 802.1x Authorization policy and click Edit.
4. From the Sub-Rules section, check that all of the options for authentication are selected including the following:
-Machine Authenticated
-User+Machine Authenticated
-User+Managed Machine 
-User+NotMachine Authenticated

If these are all configured, check that the final step is not authorized by one of the previous steps, and block traffic in accordance with the SSP by selecting "Add>".

1. Give the policy a name like "Deny Access".
2. In the Condition box, click "Add" and select "802.1x RADIUS Authentication State".
3. Check the box labeled "RADIUS-Rejected", and then click "OK".
4. In the Actions box, click "Add" and select a block action in accordance with the SSP.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36533r811426_chk'
  tag severity: 'medium'
  tag gid: 'V-233338'
  tag rid: 'SV-233338r811427_rule'
  tag stig_id: 'FORE-NC-000450'
  tag gtitle: 'SRG-NET-000148-NAC-000620'
  tag fix_id: 'F-36498r803489_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
