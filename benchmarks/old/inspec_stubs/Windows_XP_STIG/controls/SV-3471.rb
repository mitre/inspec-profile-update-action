control 'SV-3471' do
  title 'The system is configured to automatically forward error information.'
  desc 'This setting controls the reporting of errors to Microsoft and, if defined, a corporate error reporting site.  This does not interfere with the reporting of errors to the local user.  Since the contents of memory are included in this Error Report, sensitive information may be transmitted to Microsoft.  This feature should be disabled to prevent the release of such information.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings-> “Turn off Windows Error Reporting” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3471'
  tag rid: 'SV-3471r1_rule'
  tag gtitle: 'Error Reporting - Report Errors'
  tag fix_id: 'F-34260r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
