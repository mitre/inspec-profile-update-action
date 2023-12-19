control 'SV-242583' do
  title 'The Cisco ISE must be configured so that all endpoints that are allowed to bypass policy assessment are approved by the Information System Security Manager (ISSM) and documented in the System Security Plan (SSP). This is This is required for compliance with C2C Step 1.'
  desc 'Connections that bypass established security controls should be only in cases of administrative need. These procedures and use cases must be approved by the Information System Security Manager (ISSM).'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Review the posture policy to ensure mandated endpoints are being assed and if there are exceptions to the policy that they are documented and approved by the ISSM.

1. Navigate to Work Centers >> Posture >> Posture Policy.
2. Examine the enabled Posture Policies to determine if the endpoints that are mandated to be assessed will use the required policies.
3. If there is an endpoint type that should be assessed and there is a condition or conditions exempting a sub group of that endpoint type, verify that the sub group is documented and approved by the ISSM. 

If the policy will not be applied to required endpoints or if exempted endpoints are not approved and documented, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure the posture policy to assess mandated endpoints.

1. Navigate to Work Centers >> Posture >> Posture Policy.
2. Choose the drop-down located next to "Edit" on the right side of the page where you want the new policy inserted.
3. Choose "Insert new policy".
4. Define a Name.
5. Select the applicable Identity Groups.
6. Select the applicable Operating Systems configured in the requirement previously created.
7. Select the Compliance Module configured in the requirement previously created.
8. Select the Posture Type configured in the requirement previously created.
9. Select Other Conditions if used.
10. Select the Requirement ensuring there is a green check box to the left of the name indicating it is a mandatory requirement.
11. Choose "Done".
12. Choose "Save".

Note: For exceptions, a condition can be made to "Not Equal" or "Not Contains" a pattern to exempt devices from the policy.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45858r812747_chk'
  tag severity: 'medium'
  tag gid: 'V-242583'
  tag rid: 'SV-242583r812748_rule'
  tag stig_id: 'CSCO-NC-000090'
  tag gtitle: 'SRG-NET-000015-NAC-000080'
  tag fix_id: 'F-45815r803535_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
