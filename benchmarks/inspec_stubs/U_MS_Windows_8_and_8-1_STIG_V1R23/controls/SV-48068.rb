control 'SV-48068' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc 'Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only authorized users must be able to perform such translations.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Allow anonymous SID/Name translation" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44807r1_chk'
  tag severity: 'high'
  tag gid: 'V-3337'
  tag rid: 'SV-48068r1_rule'
  tag stig_id: 'WN08-SO-000050'
  tag gtitle: 'Anonymous SID/Name Translation'
  tag fix_id: 'F-41206r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
