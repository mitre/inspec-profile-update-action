control 'SV-37516' do
  title 'The at.deny file must not be empty if it exists.'
  desc 'On some systems, if there is no at.allow file and there is an empty at.deny file, then the system assumes everyone has permission to use the "at" facility.  This could create an insecure setting in the case of malicious users or system intruders.'
  desc 'fix', 'Add appropriate users to the at.deny file, or remove the empty at.deny file if an at.allow file exists.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-985'
  tag rid: 'SV-37516r1_rule'
  tag stig_id: 'GEN003300'
  tag gtitle: 'GEN003300'
  tag fix_id: 'F-31426r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
