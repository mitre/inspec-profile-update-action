control 'SV-225044' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc 'Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only authorized users must be able to perform such translations.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "LSAAnonymousNameLookup" equals "1" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Allow anonymous SID/Name translation" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26735r466034_chk'
  tag severity: 'high'
  tag gid: 'V-225044'
  tag rid: 'SV-225044r569186_rule'
  tag stig_id: 'WN16-SO-000250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26723r466035_fix'
  tag 'documentable'
  tag legacy: ['SV-88329', 'V-73665']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
