control 'SV-220952' do
  title 'Passwords for enabled local Administrator accounts must be changed at least every 60 days.'
  desc "The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. A local Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for enabled Administrator accounts on a regular basis will limit its exposure.

It is highly recommended to use Microsoft's Local Administrator Password Solution (LAPS). Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default. The AO still has the overall authority to use another equivalent capability to accomplish the check."
  desc 'check', 'Review the password last set date for the enabled local Administrator account.

On the local domain-joined workstation:

Open "PowerShell".

Enter "Get-LocalUser –Name * | Select-Object *”

If the "PasswordLastSet" date is greater than "60" days old for the local Administrator account for administering the computer/domain, this is a finding.'
  desc 'fix', "Change the enabled local Administrator account password at least every 60 days.

The use of Microsoft's LAPS is highly recommended. It may be used on domain-joined member servers to meet this requirement. The AO still has the overall authority to use another equivalent capability to accomplish the check."
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22667r890442_chk'
  tag severity: 'medium'
  tag gid: 'V-220952'
  tag rid: 'SV-220952r890444_rule'
  tag stig_id: 'WN10-SO-000280'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-22656r890443_fix'
  tag 'documentable'
  tag legacy: ['V-99555', 'SV-108659']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
