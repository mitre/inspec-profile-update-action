control 'SV-253452' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc 'Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only authorized users must be able to perform such translations.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Allow anonymous SID/Name translation" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56905r829438_chk'
  tag severity: 'high'
  tag gid: 'V-253452'
  tag rid: 'SV-253452r829440_rule'
  tag stig_id: 'WN11-SO-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56855r829439_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
