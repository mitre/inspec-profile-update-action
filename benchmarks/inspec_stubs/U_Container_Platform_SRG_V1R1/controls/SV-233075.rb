control 'SV-233075' do
  title 'The container platform must uniquely identify and authenticate users.'
  desc 'The container platform requires user accounts to perform container platform tasks. These tasks may pertain to the overall container platform or may be component-specific, thus requiring users to authenticate against those specific components. To ensure accountability and prevent unauthenticated access, users must be identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', 'Review the container platform configuration to determine if users are uniquely identified and authenticated. 

If users are not uniquely identified or are not authenticated, this is a finding.'
  desc 'fix', 'Configure the container platform to uniquely identify and authenticate users.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36011r598861_chk'
  tag severity: 'medium'
  tag gid: 'V-233075'
  tag rid: 'SV-233075r599509_rule'
  tag stig_id: 'SRG-APP-000148-CTR-000335'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-35979r598862_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
