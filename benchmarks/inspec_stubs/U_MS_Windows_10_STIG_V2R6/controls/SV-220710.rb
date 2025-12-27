control 'SV-220710' do
  title 'Non system-created file shares on a system must limit access to groups that require it.'
  desc 'Shares which provide network access, should not typically exist on a workstation except for system-created administrative shares, and could potentially expose sensitive information.  If a share is necessary, share permissions, as well as NTFS permissions, must be reconfigured to give the minimum access to those accounts that require it.'
  desc 'check', 'Non system-created shares should not typically exist on workstations.

If only system-created shares exist on the system this is NA.

Run "Computer Management".
Navigate to System Tools >> Shared Folders >> Shares.

If the only shares listed are "ADMIN$", "C$" and "IPC$", this is NA.
(Selecting Properties for system-created shares will display a message that it has been shared for administrative purposes.)

Right click any non-system-created shares.
Select "Properties".
Select the "Share Permissions" tab.

Verify the necessity of any shares found.
If the file shares have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the "Security" tab.

If the NTFS permissions have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.'
  desc 'fix', 'If a non system-created share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.

Remove any unnecessary non-system created shares.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22425r554615_chk'
  tag severity: 'medium'
  tag gid: 'V-220710'
  tag rid: 'SV-220710r569187_rule'
  tag stig_id: 'WN10-00-000060'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-22414r554616_fix'
  tag 'documentable'
  tag legacy: ['SV-77847', 'V-63357']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
