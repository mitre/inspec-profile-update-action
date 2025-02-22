control 'SV-3337' do
  title 'Anonymous SID/Name translation is allowed.'
  desc 'This is a Category 1 finding because this setting controls the ability of users or process that have authenticated as anonymous users to perform SID/Name translation.  This setting should be disabled, as only authorized users should be able to perform such translations.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.
If the value for “Network access: Allow anonymous SID/Name translation” is not set to “Disabled”, then this is a finding.
 
 
Documentable Explanation: The default setting for domain controllers is Enabled. Disabling it means that legacy systems may be unable to communicate with Windows Server 2003/2008 – based domains. This requirement should be documented with the IAO.'
  desc 'fix', 'Configure the system to disable anonymous SID/Name translation.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-152r1_chk'
  tag severity: 'high'
  tag gid: 'V-3337'
  tag rid: 'SV-3337r1_rule'
  tag gtitle: 'Anonymous SID/Name Translation'
  tag fix_id: 'F-121r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
