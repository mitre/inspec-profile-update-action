control 'SV-32264' do
  title 'File share ACLs will be reconfigured to remove the Everyone group.'
  desc 'By default, the Everyone group is given full control to new file shares. When a share is created, permissions should be reconfigured to give the minimum access to those accounts that require it.'
  desc 'check', 'Open the Computer Management Console. 
Expand the “System Tools” object in the Tree window. 
Expand the “Shared Folders” object. 
Select the “Shares” object. 
Right click any user-created shares (ignore administrative shares; the system will prompt you if Properties are selected for administrative shares). 
Select Properties. 
Select the Share Permissions tab. 

If user-created file shares have not been reconfigured to remove ACL permissions from the “Everyone” group, then this is a finding.  

Documentable Explanation: If shares created by applications require the “Everyone” group, this should be documented with the IAO.'
  desc 'fix', 'Remove permissions from the Everyone group from locally-created file shares and assign them to authorized groups.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3245'
  tag rid: 'SV-32264r1_rule'
  tag gtitle: 'File share ACLs'
  tag fix_id: 'F-59r1_fix'
  tag false_positives: 'System created shares should be excluded from the check.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
