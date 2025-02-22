control 'SV-234070' do
  title 'Documentation defining Tanium functional roles must be maintained.'
  desc 'System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of Tanium functional roles. 

If the documentation does not define functional roles, this is a finding.'
  desc 'fix', 'Consult with the Tanium System Administrator to review the documented list of Tanium functional roles. 

If the documentation does not define functional roles, this is a finding.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37255r610710_chk'
  tag severity: 'medium'
  tag gid: 'V-234070'
  tag rid: 'SV-234070r612749_rule'
  tag stig_id: 'TANS-CN-000037'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37220r610711_fix'
  tag 'documentable'
  tag legacy: ['SV-102213', 'V-92111']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
