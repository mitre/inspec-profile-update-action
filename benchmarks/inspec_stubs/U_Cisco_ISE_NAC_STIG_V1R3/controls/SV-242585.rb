control 'SV-242585' do
  title 'When endpoints fail the policy assessment, the Cisco ISE must create a record with sufficient detail suitable for forwarding to a remediation server for automated remediation or sending to the user for manual remediation. This is required for compliance with C2C Step 3.'
  desc 'Failing the NAC assessment means that an unauthorized machine has attempted to access the secure network. Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.'
  desc 'check', 'If DoD is not at C2C Step 3 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify that each requirement used has a message to display. 

1. Navigate to Work Centers >> Posture >> Posture Policy.
2. Make a note of each "Requirement" tied to an enabled Posture Policy.
3. Navigate to Work Centers >> Posture >> Policy Elements >> Requirements.
4. Verify that each requirement noted has a message in the "Message Shown to Agent User" box. 

If a requirement that is used does not have a message, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure a message prior to remediation.

1. Navigate to Work Centers >> Posture >> Policy Elements >> Requirements.
2. On the requirements under "Remediation Actions" define a message in the "Message Shown to Agent User".
3. Choose "Done".
4. Choose "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45860r812751_chk'
  tag severity: 'medium'
  tag gid: 'V-242585'
  tag rid: 'SV-242585r812752_rule'
  tag stig_id: 'CSCO-NC-000110'
  tag gtitle: 'SRG-NET-000015-NAC-000110'
  tag fix_id: 'F-45817r803541_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
