control 'SV-25006' do
  title 'File share permissions must be reconfigured to remove the Everyone group.'
  desc 'Shares on a system can provide network access, exposing sensitive information.  If a share is necessary, permissions must be reconfigured to give the minimum access to those accounts that require it.'
  desc 'check', 'Open the Computer Management Console.
Expand the "System Tools" object in the left pane.
Expand the "Shared Folders" object.
Select the "Shares" object.
Right click any user-created shares (ignore administrative shares; the system will prompt you if Properties are selected for administrative shares).
Select "Properties".
Select the "Share Permissions" tab.

If user-created file shares have not been reconfigured to remove ACL permissions from the "Everyone" group, this is a finding.

If shares created by applications require the "Everyone" group, this must be documented with the ISSO.'
  desc 'fix', 'Remove permissions from the "Everyone" group from locally-created file shares and assign them to authorized groups.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62071r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3245'
  tag rid: 'SV-25006r2_rule'
  tag gtitle: 'File share ACLs'
  tag fix_id: 'F-66969r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
