control 'SV-225491' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc 'Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only authorized users must be able to perform such translations.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Allow anonymous SID/Name translation" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27190r471815_chk'
  tag severity: 'high'
  tag gid: 'V-225491'
  tag rid: 'SV-225491r569185_rule'
  tag stig_id: 'WN12-SO-000050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27178r471816_fix'
  tag 'documentable'
  tag legacy: ['SV-52882', 'V-3337']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
