control 'SV-226063' do
  title 'The built-in Windows password complexity policy must be enabled.'
  desc 'The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least 3 of the 4 types of characters (numbers, upper- and lower-case letters, and special characters), as well as preventing the inclusion of user names or parts of.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Password must meet complexity requirements" is not set to "Enabled", this is a finding.

Note: If an external password filter is in use that enforces all 4 character types and requires this setting be set to "Disabled", this would not be considered a finding. If this setting does not affect the use of an external password filter, it must be enabled for fallback purposes.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings -> Security Settings >> Account Policies >> Password Policy >> "Password must meet complexity requirements" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27765r475512_chk'
  tag severity: 'medium'
  tag gid: 'V-226063'
  tag rid: 'SV-226063r794292_rule'
  tag stig_id: 'WN12-AC-000008'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-27753r475513_fix'
  tag 'documentable'
  tag legacy: ['SV-52863', 'V-1150']
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
