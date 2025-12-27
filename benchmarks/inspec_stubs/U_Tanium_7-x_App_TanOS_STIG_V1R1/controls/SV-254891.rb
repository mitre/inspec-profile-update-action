control 'SV-254891' do
  title 'The Tanium documentation identifying recognized and trusted SCAP sources must be maintained.'
  desc 'NIST validated SCAP XML documents are provided from several possible sources such as DISA, NIST, and the other nongovernment entities. These documents are used as the basis of compliance definitions leveraged to automate compliance auditing of systems. These documents are updated on different frequencies and must be manually downloaded on regular intervals and imported to be current. Nonapproved SCAP definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of trusted SCAP sources.

If the site does not have the "Tanium Comply" module, or does not use Tanium Comply for compliance validation, this finding is Not Applicable.

If the site does use Tanium Comply and the source for SCAP content is not documented, this is a finding.'
  desc 'fix', 'If the site does not have the Tanium Comply module, or does not use Tanium Comply for compliance validation, this finding is Not Applicable.

Prepare and maintain documentation identifying the source of SCAP sources that will be used by the Tanium Comply module.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58504r867571_chk'
  tag severity: 'medium'
  tag gid: 'V-254891'
  tag rid: 'SV-254891r867573_rule'
  tag stig_id: 'TANS-AP-000150'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-58448r867572_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
