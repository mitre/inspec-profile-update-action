control 'SV-253400' do
  title 'The use of a hardware security device with Windows Hello for Business must be enabled.'
  desc 'The use of a Trusted Platform Module (TPM) to store keys for Windows Hello for Business provides additional security. Keys stored in the TPM may only be used on that system while keys stored using software are more susceptible to compromise and could be used on other systems.'
  desc 'check', 'Virtual desktop implementations currently may not support the use of TPMs. For virtual desktop implementations where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\

Value Name: RequireSecurityDevice

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Hello for Business >> "Use a hardware security device" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56853r829282_chk'
  tag severity: 'medium'
  tag gid: 'V-253400'
  tag rid: 'SV-253400r829284_rule'
  tag stig_id: 'WN11-CC-000255'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56803r829283_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
