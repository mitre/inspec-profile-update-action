control 'SV-234117' do
  title 'The Tanium documentation identifying recognized and trusted OVAL feeds must be maintained.'
  desc 'OVAL XML documents are provided from several possible sources such as the CIS open source repository, or any number of vendor/3rd party paid repositories. These documents are used to automate the passive validation of vulnerabilities on systems and therefore require a reasonable level of confidence in their origin. Non-approved OVAL definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of trusted OVAL feeds.

If the site does not have "Tanium Comply" module, or does not use "Tanium Comply" for passive vulnerability scanning, this finding is Not Applicable.

Otherwise, if the site does use "Tanium Comply" and the source for OVAL content is not documented, this is a finding.'
  desc 'fix', 'If the site does not have "Tanium Comply" module, or does not use "Tanium Comply" for passive vulnerability scanning, this finding is Not Applicable.

Prepare and maintain documentation identifying the source of OVAL feeds that will be used by "Tanium Comply" module.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37302r610851_chk'
  tag severity: 'medium'
  tag gid: 'V-234117'
  tag rid: 'SV-234117r612749_rule'
  tag stig_id: 'TANS-SV-000051'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37267r610852_fix'
  tag 'documentable'
  tag legacy: ['SV-102307', 'V-92205']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
