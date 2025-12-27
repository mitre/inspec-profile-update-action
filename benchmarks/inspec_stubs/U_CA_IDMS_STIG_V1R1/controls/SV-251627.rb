control 'SV-251627' do
  title 'Custom database code and associated application code must reveal detailed error messages only to the Information System Security Officer (ISSO), Information System Security manager (ISSM), Systems Administrator (SA), and Database Administrator (DBA).'
  desc 'Detailed error messages issued by custom or user-written code can possibly give too much detail to the users. This code should be examined to ensure that this does not happen.'
  desc 'check', 'Check custom database code to determine if detailed error messages are ever displayed to unauthorized individuals.

If detailed error messages are displayed to individuals not authorized to view them, this is a finding.'
  desc 'fix', 'Configure custom database code and associated application code not to display detailed error messages to those not authorized to view them.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55062r807746_chk'
  tag severity: 'medium'
  tag gid: 'V-251627'
  tag rid: 'SV-251627r807748_rule'
  tag stig_id: 'IDMS-DB-000560'
  tag gtitle: 'SRG-APP-000267-DB-000163'
  tag fix_id: 'F-55016r807747_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
