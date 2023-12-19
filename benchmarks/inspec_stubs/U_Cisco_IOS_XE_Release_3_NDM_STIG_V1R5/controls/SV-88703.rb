control 'SV-88703' do
  title 'The Cisco IOS XE router must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc 'check', 'Verify that the Cisco IOS XE router is configured to reveal error messages only to authorized individuals.

The configuration should look similar to the example below:

parser view Senior-Admin
 secret 5 $1$hW3m$PE.3zCJYeSrvYflFey71R.
 commands exec include all configure
 commands exec include all show

parser view Auditor
 secret 5 $1$qb3F$SrdJW2oyyDzq1L94I7eED.
 commands exec include show logging

If it is not configured to reveal error messages only to authorized individuals, this is a finding.'
  desc 'fix', 'Use CLI views to control who can view error messages.

The configuration should look similar to the example below:

parser view Senior-Admin
 secret 5 $1$hW3m$PE.3zCJYeSrvYflFey71R.
 commands exec include all configure
 commands exec include all show

parser view Auditor
 secret 5 $1$qb3F$SrdJW2oyyDzq1L94I7eED.
 commands exec include show logging'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74119r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74029'
  tag rid: 'SV-88703r2_rule'
  tag stig_id: 'CISR-ND-000077'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-80571r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
