control 'SV-29764' do
  title 'Specified groups are not restricted.'
  desc 'The Restricted Groups option allows the administrator to manage membership of sensitive groups.  The Power Users group is one such group.  This group has been given significant privileges under Windows 2000.'
  desc 'check', 'Expand the “Security Configuration and Analysis” object in the tree window. 
Expand the “Restricted Groups” object.

Double click the value for “Power Users”.  If there are any users or groups listed under the “members” tab, then this is a finding.  If there are any groups listed under the “member of” tab, then this is a finding.'
  desc 'fix', 'Configure the system to restrict membership of the Power Users group to have no accounts or groups as members.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2375'
  tag rid: 'SV-29764r1_rule'
  tag gtitle: 'Power User Restrictions'
  tag fix_id: 'F-119r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
end
