control 'SV-205857' do
  title 'Windows Server 2019 must have Secure Boot enabled.'
  desc 'Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows, including Virtualization Based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.'
  desc 'check', 'Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a future date when broad support of Windows hardware and firmware requirements are expected to be met. Devices that have UEFI firmware must have Secure Boot enabled.  

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is a finding.

On server core installations, run the following PowerShell command:

Confirm-SecureBootUEFI

If a value of "True" is not returned, this is a finding.'
  desc 'fix', 'Enable Secure Boot in the system firmware.'
  impact 0.3
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-6122r355933_chk'
  tag severity: 'low'
  tag gid: 'V-205857'
  tag rid: 'SV-205857r569188_rule'
  tag stig_id: 'WN19-00-000470'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6122r355934_fix'
  tag 'documentable'
  tag legacy: ['SV-103319', 'V-93231']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
