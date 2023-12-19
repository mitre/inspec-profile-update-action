control 'SV-93319' do
  title 'Documentation identifying Tanium console users and their respective Computer Group rights must be maintained.'
  desc 'System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of Tanium users and their respective, approved Computer Group rights.

If the site does not have the Tanium users and their respective, approved Computer Group rights documented, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective Computer Group rights.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78613'
  tag rid: 'SV-93319r1_rule'
  tag stig_id: 'TANS-CN-000008'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-85349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
