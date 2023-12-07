control 'SV-226060' do
  title 'The maximum password age must meet requirements.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for the "Maximum password age" is greater than "60" days, this is a finding.  If the value is set to "0" (never expires), this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Maximum password age" to "60" days or less (excluding "0" which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27762r475503_chk'
  tag severity: 'medium'
  tag gid: 'V-226060'
  tag rid: 'SV-226060r794295_rule'
  tag stig_id: 'WN12-AC-000005'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-27750r475504_fix'
  tag 'documentable'
  tag legacy: ['V-1104', 'SV-52851']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
