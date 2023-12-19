control 'SV-76925' do
  title 'ColdFusion accounts with access to the Administrator Console must be approved.'
  desc 'ColdFusion offers an Administrator Console that is used to setup ColdFusion.  The console allows the administrator to setup user accounts, user privileges, logging, data sources, etc.  These accounts, once setup, do not automatically lock after a set duration of inactivity or any other security event that would require automatic locking or deletion.  This would enable an account for a user who either left the organization or changed job roles, to continue access the console until the account is manually deleted.

To make certain that the user accounts are only those that are needed, the accounts must be approved by the ISSM.'
  desc 'check', 'Review the users within the "User Manager" page under the "Security" menu.

If users exist that are not approved by the ISSM, this is a finding.'
  desc 'fix', 'Navigate to the "User Manager" page under the "Security" menu.  Modify the list of users to only contain those approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62435'
  tag rid: 'SV-76925r1_rule'
  tag stig_id: 'CF11-03-000112'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68355r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
