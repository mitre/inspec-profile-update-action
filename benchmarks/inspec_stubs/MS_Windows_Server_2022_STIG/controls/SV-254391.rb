control 'SV-254391' do
  title 'Windows Server 2022 permissions on the Active Directory data files must only allow System and Administrators access.'
  desc 'Improper access permissions for directory data-related files could allow unauthorized users to read, modify, or delete directory data or audit trails.

'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Run "Regedit".

Navigate to "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters".

Note the directory locations in the values for:

Database log files path
DSA Database file

By default, they will be \\Windows\\NTDS.

If the locations are different, the following will need to be run for each.

Open "Command Prompt (Admin)".

Navigate to the NTDS directory (\\Windows\\NTDS by default).

Run "icacls *.*".

If the permissions on each file are not as restrictive as the following, this is a finding:

NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access'
  desc 'fix', 'Maintain the permissions on NTDS database and log files as follows:

NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57876r848987_chk'
  tag severity: 'high'
  tag gid: 'V-254391'
  tag rid: 'SV-254391r877392_rule'
  tag stig_id: 'WN22-DC-000070'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57827r848988_fix'
  tag satisfies: ['SRG-OS-000324-GPOS-00125', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-001314', 'CCI-002235']
  tag nist: ['SI-11 b', 'AC-6 (10)']
end
