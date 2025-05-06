control 'SV-254284' do
  title 'Windows Server 2022 must have Secure Boot enabled.'
  desc 'Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows, including Virtualization Based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.'
  desc 'check', 'Devices that have UEFI firmware must have Secure Boot enabled.

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.

On server core installations, run the following PowerShell command:

Confirm-SecureBootUEFI

If a value of "True" is not returned, this is a finding.'
  desc 'fix', 'Enable Secure Boot in the system firmware.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57769r848666_chk'
  tag severity: 'medium'
  tag gid: 'V-254284'
  tag rid: 'SV-254284r848668_rule'
  tag stig_id: 'WN22-00-000470'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57720r848667_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
