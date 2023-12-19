control 'SV-48543' do
  title 'File shares must be limited on a system.'
  desc 'Shares on a system can provide network access, exposing sensitive information.  If a share is necessary, share permissions, as well as NTFS permissions, must be reconfigured to give the minimum access to those accounts that require it.'
  desc 'check', 'Open the Computer Management Console.
Expand the "System Tools" object in the Tree window.
Expand the "Shared Folders" object.
Select the "Shares" object.
Right click any non-system-created shares (the system will prompt you if Properties are selected for system-created shares).
Select Properties.
Select the Share Permissions tab.

Verify the necessity of any shares found.  If the file shares have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the Security tab.

If the NTFS permissions have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.'
  desc 'fix', 'If a share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.

Remove any unnecessary non-system created shares.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44806r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3245'
  tag rid: 'SV-48543r1_rule'
  tag stig_id: 'WN08-GE-000015'
  tag gtitle: 'File share ACLs'
  tag fix_id: 'F-41205r1_fix'
  tag false_positives: 'System created shares should be excluded from the check.'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
