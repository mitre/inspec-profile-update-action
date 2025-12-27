control 'SV-224841' do
  title 'Non-system-created file shares on a system must limit access to groups that require it.'
  desc 'Shares on a system provide network access. To prevent exposing sensitive information, where shares are necessary, permissions must be reconfigured to give the minimum access to accounts that require it.'
  desc 'check', 'If only system-created shares such as "ADMIN$", "C$", and "IPC$" exist on the system, this is NA. (System-created shares will display a message that it has been shared for administrative purposes when "Properties" is selected.)

Run "Computer Management".

Navigate to System Tools >> Shared Folders >> Shares.

Right-click any non-system-created shares.

Select "Properties".

Select the "Share Permissions" tab.

If the file shares have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the "Security" tab.

If the permissions have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding.'
  desc 'fix', 'If a non-system-created share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.

Remove any unnecessary non-system-created shares.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26532r465425_chk'
  tag severity: 'medium'
  tag gid: 'V-224841'
  tag rid: 'SV-224841r569186_rule'
  tag stig_id: 'WN16-00-000250'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-26520r465426_fix'
  tag 'documentable'
  tag legacy: ['V-73267', 'SV-87919']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
