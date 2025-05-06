control 'SV-51469' do
  title 'The organization must document and gain approval from the Change Control Authority prior to migrating data to DoD operational networks.'
  desc 'Without the approval of the Change Control Authority, data moved from the test and development network into an operational network could pose a risk of containing malicious code or cause other unintended consequences to live operational data.  Data moving into operational networks from final stage preparation must always be vetted and approved.'
  desc 'check', "Review the change control documentation for the environment to determine whether the organization has prior approval to move data from the test and development environment to the operational network after final testing.  If the organization does not keep a change control log or the log exists but is not current, this is a finding.

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Create a policy to document all finalized projects to gain approval by the Change Control Authority prior to deploying finalized projects to a DoD operational network.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46796r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39611'
  tag rid: 'SV-51469r1_rule'
  tag stig_id: 'ENTD0120'
  tag gtitle: 'ENTD0120 - Applications moving to operational networks not approved.'
  tag fix_id: 'F-44627r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1, ECSD-1, ECSD-2'
end
