control 'SV-93441' do
  title 'The Tanium documentation identifying recognized and trusted SCAP feeds must be maintained.'
  desc 'NIST validated SCAP XML documents are provided from several possible sources such as DISA, NIST, and the other non-government entities. These documents are used as the basis of compliance definitions leveraged to automate compliance auditing of systems. These documents are updated on different frequencies and must be manually downloaded on regular intervals and imported in order to be current. Non-approved SCAP definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of trusted SCAP feeds.

If the site does not have "Tanium Comply" module, or does not use "Tanium Comply" for compliance validation, this finding is "Not Applicable".

If the site does use "Tanium Comply" and the source for SCAP content is not documented, this is a finding.'
  desc 'fix', 'If the site does not have "Tanium Comply" module, or does not use "Tanium Comply" for compliance validation, this finding is "Not Applicable".

Prepare and maintain documentation identifying the source of SCAP feeds that will be used by "Tanium Comply" module.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78735'
  tag rid: 'SV-93441r1_rule'
  tag stig_id: 'TANS-SV-000050'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-85477r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
