control 'SV-226070' do
  title 'Active Directory data files must have proper access control permissions.'
  desc 'Improper access permissions for directory data related files could allow unauthorized users to read, modify, or delete directory data or audit trails.'
  desc 'check', 'Verify the permissions on the content of the NTDS directory.

Open the registry editor (regedit).
Navigate to HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters.
Note the directory locations in the values for:
Database log files path
DSA Database file

By default they will be \\Windows\\NTDS. If the locations are different, the following will need to be run for each.

Open an elevated command prompt (Win+x, Command Prompt (Admin)).
Navigate to the NTDS directory (\\Windows\\NTDS by default).
Run "icacls *.*".

If the permissions on each file are not at least as restrictive as the following, this is a finding.

NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access

Do not use File Explorer to attempt to view permissions of the NTDS folder. Accessing the folder through File Explorer will change the permissions on the folder.'
  desc 'fix', 'Ensure the permissions on NTDS database and log files are at least as restrictive as the following:
NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27772r475533_chk'
  tag severity: 'high'
  tag gid: 'V-226070'
  tag rid: 'SV-226070r794318_rule'
  tag stig_id: 'WN12-AD-000001-DC'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27760r475534_fix'
  tag 'documentable'
  tag legacy: ['SV-51175', 'V-8316']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
