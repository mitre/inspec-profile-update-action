control 'SV-38996' do
  title 'Data files owned by users must be on a different logical partition from the directory server data files.'
  desc 'When directory service data files, especially for directories used for identification, authentication, or authorization, reside on the same logical partition as user-owned files, the directory service data may be more vulnerable to unauthorized access or other availability compromises.  Directory service and user-owned data files sharing a partition may be configured with less restrictive permissions in order to allow access to the user data. 

The directory service may be vulnerable to a denial of service attack when user-owned files on a common partition are expanded to an extent preventing the directory service from acquiring more space for directory or audit data.'
  desc 'check', 'Refer to the AD database location obtained in check V-8316. Note the logical drive (e.g., C:) on which the files are located.

Determine if the server is currently providing file sharing services to users with the following command.
Enter "net share" at a command prompt.

Note the logical drive(s) or file system partition for any site-created data shares.
Ignore all system shares (e.g., Windows NETLOGON, SYSVOL, and administrative shares ending in $). User shares that are hidden (ending with $) should not be ignored.

If user shares are located on the same logical partition as the directory server data files, this is a finding.'
  desc 'fix', 'Ensure files owned by users are stored on a different logical partition then the directory server data files.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-48684r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8317'
  tag rid: 'SV-38996r2_rule'
  tag stig_id: 'DS00.1190_2008_R2'
  tag gtitle: 'Directory Server Data File Locations'
  tag fix_id: 'F-47807r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
