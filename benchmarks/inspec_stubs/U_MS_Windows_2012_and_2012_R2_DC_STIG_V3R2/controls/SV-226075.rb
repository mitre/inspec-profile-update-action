control 'SV-226075' do
  title 'Data files owned by users must be on a different logical partition from the directory server data files.'
  desc 'When directory service data files, especially for directories used for identification, authentication, or authorization, reside on the same logical partition as user-owned files, the directory service data may be more vulnerable to unauthorized access or other availability compromises.  Directory service and user-owned data files sharing a partition may be configured with less restrictive permissions in order to allow access to the user data. 

The directory service may be vulnerable to a denial of service attack when user-owned files on a common partition are expanded to an extent preventing the directory service from acquiring more space for directory or audit data.'
  desc 'check', 'Refer to the AD database location obtained in check V-8316.  Note the logical drive (e.g., C:) on which the files are located.

Determine if the server is currently providing file sharing services to users with the following command.
Enter "net share" at a command prompt.

Note the logical drive(s) or file system partition for any site-created data shares.
Ignore all system shares (e.g., Windows NETLOGON, SYSVOL, and administrative shares ending in $). User shares that are hidden (ending with $) should not be ignored.

If user shares are located on the same logical partition as the directory server data files, this is a finding.'
  desc 'fix', 'Ensure files owned by users  are stored on a different logical partition then the directory server data files.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27777r475548_chk'
  tag severity: 'medium'
  tag gid: 'V-226075'
  tag rid: 'SV-226075r569184_rule'
  tag stig_id: 'WN12-AD-000006-DC'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27765r475549_fix'
  tag 'documentable'
  tag legacy: ['SV-51180', 'V-8317']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
