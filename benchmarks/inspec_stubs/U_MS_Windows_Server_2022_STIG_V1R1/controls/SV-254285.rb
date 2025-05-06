control 'SV-254285' do
  title 'Windows Server 2022 account lockout duration must be configured to 15 minutes or greater.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "LockoutDuration" is less than "15" (excluding "0") in the file, this is a finding.

Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> Account lockout duration to "15" minutes or greater.

A value of "0" is also acceptable, requiring an administrator to unlock the account.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57770r848669_chk'
  tag severity: 'medium'
  tag gid: 'V-254285'
  tag rid: 'SV-254285r848671_rule'
  tag stig_id: 'WN22-AC-000010'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-57721r848670_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
