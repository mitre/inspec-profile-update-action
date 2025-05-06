control 'SV-233269' do
  title 'The container platform must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to generate audit records for all account creations, modifications, disabling, and termination events. 

If the container platform is not configured to generate the audit records, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records for all account creations, modifications, disabling, and termination events.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36205r599728_chk'
  tag severity: 'medium'
  tag gid: 'V-233269'
  tag rid: 'SV-233269r599728_rule'
  tag stig_id: 'SRG-APP-000509-CTR-001305'
  tag gtitle: 'SRG-APP-000509'
  tag fix_id: 'F-36173r599444_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
