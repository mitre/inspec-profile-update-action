control 'SV-220702' do
  title 'Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.'
  desc 'If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running.'
  desc 'check', 'Verify all Windows 10 information systems (including SIPRNet) employ BitLocker for full disk encryption.

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
For WVD implementations with no data at rest, this is NA.

If full disk encryption using BitLocker is not implemented, this is a finding.

Verify BitLocker is turned on for the operating system drive and any fixed data drives.

Open "BitLocker Drive Encryption" from the Control Panel.

If the operating system drive or any fixed data drives have "Turn on BitLocker", this is a finding.

NOTE: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full disk encryption and satisfies the pre-boot authentication requirements (WN10-00-000031 and WN10-00-000032).'
  desc 'fix', 'Enable full disk encryption on all information systems (including SIPRNet) using BitLocker.

BitLocker, included in Windows, can be enabled in the Control Panel under "BitLocker Drive Encryption" as well as other management tools.

NOTE: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full disk encryption and satisfies the pre-boot authentication requirements (WN10-00-000031 and WN10-00-000032).'
  impact 0.5
  ref 'DPMS Target Windows 10'
  tag check_id: 'C-22417r603151_chk'
  tag severity: 'medium'
  tag gid: 'V-220702'
  tag rid: 'SV-220702r569228_rule'
  tag stig_id: 'WN10-00-000030'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-22406r554592_fix'
  tag 'documentable'
  tag legacy: ['SV-77827', 'V-63337']
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
