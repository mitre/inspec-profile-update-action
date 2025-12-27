control 'SV-20644' do
  title 'Email Configuration Management (CM) procedures must be implemented.'
  desc 'Uncontrolled, untested, or unmanaged changes can result in an unreliable security posture. All software libraries related to email services must be reviewed, considered, and the responsibility for CM assigned to ensure no libraries or configurations are left unaddressed. This is true even if CM responsibilities appear to cross organizational boundaries. 

Ensure patches, configurations, and upgrades are addressed. Process steps should have specific procedures and responsibilities assigned to individuals.'
  desc 'check', 'Access the EDSP and confirm CM procedures and assignments are documented.  Examine artifacts that show the processes have been implemented.  

If CM procedures are documented and implemented, this is not a finding.'
  desc 'fix', 'Document Configuration Management procedures in the EDSP.  Implement the CM procedures as documented.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22457r2_chk'
  tag severity: 'medium'
  tag gid: 'V-18864'
  tag rid: 'SV-20644r3_rule'
  tag stig_id: 'EMG3-045 EMail'
  tag gtitle: 'EMG3-045 Email Configuration Management'
  tag fix_id: 'F-19570r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'DCPR-1'
end
