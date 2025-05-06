control 'SV-51299' do
  title 'A change management policy must be implemented for application development.'
  desc 'Change management is the formal review process that ensures that all changes made to a system or application receives formal review and approval.  Change management reduces impacts from proposed changes that could possibly have interruptions to the services provided.  Recording all changes for applications will be accomplished by a configuration management policy.  The configuration management policy will capture the actual changes to software code and anything else affected by the change.'
  desc 'check', "Interview the ISSM/ISSO to determine whether a current Change Control Management policy has been implemented in the organization.  If a change management policy has not been created and implemented for the organization, this is a finding.

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Create a change management policy for the organization for application and system development.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46716r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39441'
  tag rid: 'SV-51299r1_rule'
  tag stig_id: 'ENTD0110'
  tag gtitle: 'ENTD0110 - A change management policy is not implemented.'
  tag fix_id: 'F-44454r2_fix'
  tag 'documentable'
  tag ia_controls: 'DCII-1, DCPR-1'
end
