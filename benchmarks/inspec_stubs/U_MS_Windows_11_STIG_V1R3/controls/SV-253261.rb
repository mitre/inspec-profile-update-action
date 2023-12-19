control 'SV-253261' do
  title 'Windows 11 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.'
  desc 'If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing encrypted drives. Increasing the pin length requires a greater number of guesses for an attacker.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

For AVD implementations with no data at rest, this is NA.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\

Value Name: MinimumPIN
Type: REG_DWORD
Value: 0x00000006 (6) or greater'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> BitLocker Drive Encryption >> Operating System Drives "Configure minimum PIN length for startup" to "Enabled" with "Minimum characters:" set to "6" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56714r828865_chk'
  tag severity: 'medium'
  tag gid: 'V-253261'
  tag rid: 'SV-253261r828867_rule'
  tag stig_id: 'WN11-00-000032'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-56664r828866_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
