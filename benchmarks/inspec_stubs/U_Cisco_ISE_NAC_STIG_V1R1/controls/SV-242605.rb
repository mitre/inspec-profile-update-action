control 'SV-242605' do
  title 'The Cisco ISE must enforce posture status assessment for posture retired clients defined in the NAC System Security Plan (SSP).'
  desc 'Posture assessments can reduce the risk that clients impose on networks by restricting or preventing access of noncompliant clients. If the posture assessment is not enforced, then access of clients not complying is not restricted allowing the risk of vulnerabilities being exposed.'
  desc 'check', 'Verify the authorization policy will enforce posture assessment status for posture required clients.

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set.
3. Expand the Authorization Policy.
4. Verify that a rule with the condition "Session-PostureStatus EQUALS NonCompliant" is present and will apply to posture required devices by analyzing other conditions used on the same policy.
5. Ensure the result that is used for remediation access is a restricted VLAN, ACL, SGT, or any combination used to restrict the access.

If there is not an authorization policy for NonCompliant clients that are posture required, this is a finding. 

If the authorization policy does not restrict the access of NonCompliant clients that are posture required, this is a finding.'
  desc 'fix', 'Configure the authorization policy to enforce posture assessment status for posture required clients.

1. Edit the Policy Set to enforce the posture assessment.
2. Navigate to Work Centers >> Network Access >> Policy Sets.
3. Choose ">" on the applicable policy set.
4. Expand the Authorization Policy.
5. Click on Actions Gear below to location where the new Authorization Policy will be inserted.
6. Choose "Insert new role above", or if there is an Authorization Policy made for the device type that posture will be applied to, choose "Duplicate above".
7. Click on the name of the policy and define a desirable name.
8 Either click on the "+" icon or click on the existing Conditions to open the Conditions Studio.
9. Choose "New" under the editor.
10. Choose "Click to add an attribute".
11. Under Dictionary, select "Session" in the drop-down menu.
12. Under Attribute, select "PostureStatus".
13. Ensure "Equals" is selected as the operator. 
14. Select "Compliant" in the drop-down menu.
15. Choose "New".
16. Add a condition to flag the device type that should be postured.
17. Choose "Use".
18. Name the rule accordingly.
19. Select the desired result.
20. Click on Actions Gear on the Authorization Policy just created.
21. Select Duplicate below in the drop-down.
22. Click on the conditions of the copy.
23. Change the PostureStatus variable form "Compliant" to "NonCompliant".
24. Choose "Use".
25. Name the rule accordingly.
26. Select a result that is used for remediation access, which should be a result that is configured for a restricted VLAN, ACL, SGT, or any combination used to restrict the access.
27. Choose "Save".'
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45880r714123_chk'
  tag severity: 'high'
  tag gid: 'V-242605'
  tag rid: 'SV-242605r714125_rule'
  tag stig_id: 'CSCO-NC-000310'
  tag gtitle: 'SRG-NET-000512-NAC-002310'
  tag fix_id: 'F-45837r714124_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
