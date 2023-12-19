control 'SV-253301' do
  title 'The maximum password age must be configured to 60 days or less.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.  Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Maximum password age" is greater than "60" days, this is a finding. If the value is set to "0" (never expires), this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Maximum Password Age" to "60" days or less (excluding "0" which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56754r828985_chk'
  tag severity: 'medium'
  tag gid: 'V-253301'
  tag rid: 'SV-253301r828987_rule'
  tag stig_id: 'WN11-AC-000025'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-56704r828986_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
