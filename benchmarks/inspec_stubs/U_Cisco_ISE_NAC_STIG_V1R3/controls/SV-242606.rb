control 'SV-242606' do
  title 'The Cisco ISE must have a posture policy for posture required clients defined in the NAC System Security Plan (SSP). This is required for compliance with C2C Step 1.'
  desc 'Posture assessments can reduce the risk that clients impose on networks. The posture policy is the function that can link requirements to applicable clients. Multiple requirements can be associated with a single policy. However, multiple polices can also be applicable to the same client. The posture policy operates in such a way that all applicable policies are applied, versus the top-down first match approach.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify the posture policy for posture required clients.

1. Navigate to Work Centers >> Posture >> Posture Policy.
2. Review the enabled posture policies to ensure posture required endpoints will process requirements.

If there is not an enabled policy that will be applied to posture required endpoints, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure the posture policy for posture required clients.

1. Navigate to Work Centers >> Posture >> Posture Policy.
2. Choose the drop-down located next to "Edit" on the right side of the page where you want the new policy inserted.
3. Choose "Insert new policy".
4. Define a Name.
5. Select the applicable Identity Groups. 
6. Select the applicable Operating Systems configured in the requirement previously created.
7. Select the Compliance Module configured in the requirement previously created.
8. Select the Posture Type configured in the requirement previously created.
9. Select Other Conditions if used.
10. Select the applicable Requirement or Requirements, ensuring there is a green check box to the left of the name indicating it is a mandatory requirement.
11. Choose "Done".
12. Choose "Save".

Note: The user can apply multiple requirements to a single policy, or have multiple policies with a single policy with a single requirement as the posture policy operates in a "match-all" fashion.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45881r812793_chk'
  tag severity: 'high'
  tag gid: 'V-242606'
  tag rid: 'SV-242606r812794_rule'
  tag stig_id: 'CSCO-NC-000320'
  tag gtitle: 'SRG-NET-000512-NAC-002310'
  tag fix_id: 'F-45838r803571_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
