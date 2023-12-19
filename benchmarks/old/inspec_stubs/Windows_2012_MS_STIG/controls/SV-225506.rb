control 'SV-225506' do
  title 'The system must be configured to force users to log off when their allowed logon hours expire.'
  desc 'Limiting logon hours can help protect data by only allowing access during specified times.  This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, this must be enforced.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Network security: Force logoff when logon hours expire" is not set to "Enabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Force logoff when logon hours expire" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27205r471860_chk'
  tag severity: 'medium'
  tag gid: 'V-225506'
  tag rid: 'SV-225506r569185_rule'
  tag stig_id: 'WN12-SO-000066'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-27193r471861_fix'
  tag 'documentable'
  tag legacy: ['V-3380', 'SV-52893']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
