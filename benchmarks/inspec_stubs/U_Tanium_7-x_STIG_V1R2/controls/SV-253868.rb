control 'SV-253868' do
  title 'The Tanium documentation identifying recognized and trusted Open Vulnerability and Assessment Language (OVAL) feeds must be maintained.'
  desc 'OVAL XML documents are provided from several possible sources such as the Community Intercomparison Suite (CIS) open-source repository and vendor/third-party paid repositories. These documents are used to automate the passive validation of vulnerabilities on systems and therefore require a reasonable level of confidence in their origin. Nonapproved OVAL definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Consult with the Tanium system administrator to review the documented list of trusted OVAL feeds.

If the site does not have the "Tanium Comply" module or does not use "Tanium Comply" for passive vulnerability scanning, this finding is not applicable.

If the site does use "Tanium Comply" and the source for OVAL content is not documented, this is a finding.'
  desc 'fix', 'If the site does not have the "Tanium Comply" module or does not use "Tanium Comply" for passive vulnerability scanning, this finding is not applicable.

Prepare and maintain documentation identifying the source of OVAL feeds that will be used by the "Tanium Comply" module.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57320r842630_chk'
  tag severity: 'medium'
  tag gid: 'V-253868'
  tag rid: 'SV-253868r842632_rule'
  tag stig_id: 'TANS-SV-000051'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-57271r842631_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
