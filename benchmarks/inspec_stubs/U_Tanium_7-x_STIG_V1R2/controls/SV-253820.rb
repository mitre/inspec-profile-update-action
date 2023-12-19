control 'SV-253820' do
  title 'Documentation identifying Tanium console users and their respective Computer Group rights must be maintained.'
  desc 'System access should be reviewed periodically to verify all Tanium users are assigned the appropriate computer groups, with the least privileged access possible to perform assigned tasks. Users who have been removed from the documentation should no longer be configured as a Tanium Console User.'
  desc 'check', 'Consult with the Tanium system administrator to review the documented list of Tanium users and their respective, approved Computer Group rights.

If the documented list does not have the Tanium users and their respective, approved Computer Group rights documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective Computer Group rights.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57272r842486_chk'
  tag severity: 'medium'
  tag gid: 'V-253820'
  tag rid: 'SV-253820r842488_rule'
  tag stig_id: 'TANS-CN-000008'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-57223r842487_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
