control 'SV-226249' do
  title 'Non system-created file shares on a system must limit access to groups that require it.'
  desc 'Shares on a system provide network access.  To prevent exposing sensitive information, where shares are necessary, permissions must be reconfigured to give the minimum access to those accounts that require it.'
  desc 'check', 'If only system-created shares such as "ADMIN$", "C$", and "IPC$" exist on the system, this is NA.
(System-created shares will display a message that it has been shared for administrative purposes when "Properties" is selected.)

Run "Computer Management".
Navigate to System Tools >> Shared Folders >> Shares.

Right click any non-system-created shares.
Select "Properties".
Select the "Share Permissions" tab.

If the file shares have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the "Security" tab.

If the NTFS permissions have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.'
  desc 'fix', 'If a non-system-created share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.

Remove any unnecessary non-system-created shares.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27951r476591_chk'
  tag severity: 'medium'
  tag gid: 'V-226249'
  tag rid: 'SV-226249r569184_rule'
  tag stig_id: 'WN12-GE-000018'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27939r476592_fix'
  tag 'documentable'
  tag legacy: ['SV-52881', 'V-3245']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
