control 'SV-253867' do
  title 'The Tanium documentation identifying recognized and trusted Security Content Automation Protocol (SCAP) sources must be maintained.'
  desc 'SCAP XML documents validated by the National Institute of Standards and Technology (NIST) are provided from several possible sources such as DISA, NIST, and nongovernment entities. These documents are used as the basis of compliance definitions leveraged to automate compliance auditing of systems. These documents are updated on different frequencies and must be downloaded manually at regular intervals and imported in order to be current. Nonapproved SCAP definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Consult with the Tanium system administrator to review the documented list of trusted SCAP sources.

If the site does not have the "Tanium Comply" module or does not use "Tanium Comply" for compliance validation, this finding is not applicable.

If the site does use Tanium Comply and the source for SCAP content is not documented, this is a finding.'
  desc 'fix', 'If the site does not have the "Tanium Comply" module or does not use "Tanium Comply" for compliance validation, this finding is not applicable.

Prepare and maintain documentation identifying the source of SCAP sources that will be used by the "Tanium Comply" module.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57319r842627_chk'
  tag severity: 'medium'
  tag gid: 'V-253867'
  tag rid: 'SV-253867r842629_rule'
  tag stig_id: 'TANS-SV-000050'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-57270r842628_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
