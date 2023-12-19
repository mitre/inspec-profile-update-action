control 'SV-103617' do
  title 'Windows Server 2019 non-system-created file shares must limit access to groups that require it.'
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
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92847r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93531'
  tag rid: 'SV-103617r1_rule'
  tag stig_id: 'WN19-00-000230'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-99775r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
