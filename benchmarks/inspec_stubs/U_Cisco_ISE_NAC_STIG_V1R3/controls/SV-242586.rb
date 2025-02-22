control 'SV-242586' do
  title 'The Cisco ISE must place client machines on the blacklist and terminate the agent connection when critical security issues are found that put the network at risk. This is required for compliance with C2C Step 4.'
  desc 'Since the Cisco ISE devices and servers should have no legitimate reason for communicating with other devices outside of the assessment solution, any direct communication with unrelated hosts would be suspect traffic.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify that blacklisted devices will be denied access or quarantined. 

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set.
3. Expand the "Authorization Policy – Global Exceptions".
4. Verify that a rule with the condition "Session-ANCPolicy EQUALS <Configured ANC Policy>", or "IdentityGroup-Name EQUALS Endpoint Identity Group:Blacklist" is present with a result that will deny access or quarantine the endpoint.

If the enforcement is completed in the Authorization Policy versus the Global Exceptions, then each policy set must contain a policy for blacklisted endpoints.

If there is not an authorization policy for Blacklist endpoints, this is a finding.

If the authorization policy does not restrict or deny the access of blacklisted endpoints, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure an Adaptive Network Control (ANC) policy to deny blacklisted devices access or make an authorization policy for the blacklist endpoint identity group.

1. Navigate to Operations >> Adaptive Network Control >> Policy List.
2. Choose "Add".
3. Give the policy a name.
4. Select the desired ANC Action (QUARANTINE or RE_AUTHENTICATE are the recommended actions for this).
5. Choose "Submit".
6. Configure the authorization policy to enforce the ANC policy.
Note: If the blacklist Identity group is use vs and ANC policy, then a Change of Authorization (CoA) will need to be triggered.
7. Navigate to Work Centers >> Network Access >> Policy Sets.
8. Choose ">" on any policy set.
9. Expand "Authorization Policy – Global Exceptions".
10. Click on Actions Gear below to location the new Authorization Policy will be inserted (If there is not an existing policy, click on the "+" icon and skip the next step.)
11. Choose "Insert new role above".
12. Click on the name of the policy and define a desirable name.
13. Either click on the "+" icon or click on the existing Conditions to open the Conditions Studio.
14. Choose "New" under the editor.
15. Choose "Click to add an attribute".
16. Under Dictionary select Session in the drop-down.
17. Under Attribute select "ANCPolicy".
18. Ensure "Equals" is selected as the operator.
19. Select the desired ANC Policy in the drop-down menu.
20. Choose "Use".
21. Name the rule accordingly.
22. Select the desired result.
23. Choose "Save".

If the Blacklist Endpoint Identity Group will be used, follow these:
1. Configure the authorization policy to enforce the ANC policy.
2. Navigate to Work Centers >> Network Access >> Policy Sets.
3. Choose ">" on any policy set.
4. Expand "Authorization Policy – Global Exceptions".
5. Click on Actions Gear below to location the new Authorization Policy will be inserted (If there is not an existing policy, click on the "+" icon and skip the next step.)
6. Choose "Insert new role above".
7. Click on the name of the policy and define a desirable name.
8. Either click on the "+" icon or click on the existing Conditions to open the Conditions Studio.
9. Choose "New" under the editor.
10. Choose "Click to add an attribute".
11. Under Dictionary select "IdentityGroup" in the drop-down menu.
12. Under Attribute select "Name".
13. Ensure "Equals" is selected as the operator. 
14. Select "Endpoint Identity Groups:Blacklist" in the drop-down menu.
15. Choose "Use".
16. Name the rule accordingly.
17. Select the desired result.
18. Choose "Save".

Note: If the blacklist identity group is used versus an ANC policy, then a Change of Authorization (CoA) will need to be triggered.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45861r812753_chk'
  tag severity: 'medium'
  tag gid: 'V-242586'
  tag rid: 'SV-242586r812754_rule'
  tag stig_id: 'CSCO-NC-000120'
  tag gtitle: 'SRG-NET-000015-NAC-000120'
  tag fix_id: 'F-45818r803544_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
