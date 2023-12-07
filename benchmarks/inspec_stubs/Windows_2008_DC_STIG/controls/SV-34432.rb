control 'SV-34432' do
  title 'Active Directory data files must have proper access control permissions.'
  desc 'Improper access permissions for directory data related files could allow unauthorized users to read, modify, or delete directory data or audit trails.'
  desc 'check', 'Verify the permissions on the content of the NTDS directory.

Open the registry editor (regedit).
Navigate to HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters.
Note the directory locations in the values for:
Database log files path
DSA Database file

By default they will be \\Windows\\NTDS. If the locations are different, the following will need to be run for each.

Open an elevated command prompt (run as administrator).
Navigate to the NTDS directory (\\Windows\\NTDS by default).
Run "icacls *.*".

If the permissions on each file are not at least as restrictive as the following, this is a finding.

NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access

Do not use Windows Explorer to attempt to view permissions of the NTDS folder. Accessing the folder through Windows Explorer will change the permissions on the folder.'
  desc 'fix', 'Ensure the permissions on NTDS database and log files are at least as restrictive as the following:
NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-74031r2_chk'
  tag severity: 'high'
  tag gid: 'V-8316'
  tag rid: 'SV-34432r5_rule'
  tag stig_id: 'DS00.0120_2008'
  tag gtitle: 'Data File Access Permissions'
  tag fix_id: 'F-80449r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
