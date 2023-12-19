control 'SV-242588' do
  title 'The Cisco ISE must deny or restrict access for endpoints that fail required posture checks.'
  desc 'Devices, which do not meet minimum-security configuration requirements, pose a risk to the DoD network and information assets.

Endpoint devices must be disconnected or given limited access as designated by the approval authority and system owner if the device fails the authentication or security assessment. The user will be presented with a limited portal, which does not include access options for sensitive resources. Required security checks must implement DoD policy requirements.'
  desc 'check', 'Verify that the Policy Set will enforce the posture assessment. 

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set. 
3. Expand the Authorization Policy.
4. Verify that the Attribute of PostureStatus of NonCompliant is configured in the policy.
5. Make a note of the result/results on the NonCompliant Policy.
6. Navigate to Policy >> Policy >> Elements >> Results >> Authorization.
7. Expand Authorization.
8. Choose Authorization Profiles.
9. View the Standard Authorization Profile/Profiles noted above to ensure that a remediation VLAN, Access Control List, Scalable Group Tag, or any combination of these are used to restrict access.

If there is not a "NonCompliant" authorization rule or the result is not restrictive, this is a finding.'
  desc 'fix', 'Configure the Policy Set to enforce the posture assessment. 

1. Navigate to Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the applicable policy set.
3. Expand the Authorization Policy.
4. Click on Actions Gear below to location the new Authorization Policy will be inserted.
5. Choose "Insert new role above" or if there is an Authorization Policy made for the device type that that posture will be applied to choose "Duplicate above".
6. Click on the name of the policy and define a desirable name.
7. Either click on the "+" icon or click on the existing Conditions to open the Conditions Studio.
8. Choose "New" under the editor.
9. Choose "Click to add an attribute".
10. Under Dictionary select Session in the drop-down.
11. Under Attribute select PostureStatus.
12. Ensure "Equals" is selected as the operator. 
13. Select Compliant in the drop-down.
14. Choose "New".
15. Add a condition to flag the device type that should be postured.
16. Choose "Use".
17. Name the rule accordingly.
18. Select the desired result.
19. Click on Actions Gear on the Authorization Policy just created.
20. Select Duplicate below in the drop-down menu.
21. Click on the conditions of the copy.
22. Change the PostureStatus variable form "Compliant" to "NonCompliant".
23. Choose "Use".
24. Name the rule accordingly.
25. Select a result that is used for remediation access, which should be a result that is configured for a remediation VLAN, Access Control List, Scalable Group Tag, or any combination of these that are used to restrict access.
26. Choose "Save".

Note: There are several ways this can be configured to meet the requirement. This is just an example. The main thing is to have a "Compliant" and a "NonCompliant" rule using the PostureStatus conditions.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45863r714072_chk'
  tag severity: 'medium'
  tag gid: 'V-242588'
  tag rid: 'SV-242588r714074_rule'
  tag stig_id: 'CSCO-NC-000140'
  tag gtitle: 'SRG-NET-000322-NAC-001230'
  tag fix_id: 'F-45820r714073_fix'
  tag 'documentable'
  tag cci: ['CCI-002179']
  tag nist: ['AC-3 (8)']
end
