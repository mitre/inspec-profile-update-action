control 'SV-68889' do
  title 'The ALG must identify and log internal users associated with denied outgoing communications traffic posing a threat to external information systems.'
  desc 'Without identifying the users who initiated the traffic, it would be difficult to identify those responsible for the denied communications.

This requirement applies to those network elements that perform Data Leakage Prevention (DLP) (e.g., ALGs, proxies, or application level firewalls).'
  desc 'check', 'Verify the ALG identifies and logs internal users associated with denied outgoing communications traffic posing a threat to external information systems.

If the ALG does not identify and log internal users associated with denied outgoing communications traffic posing a threat to external information systems, this is a finding.'
  desc 'fix', 'Configure the ALG to identify and log internal users associated with denied outgoing communications traffic posing a threat to external information systems.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54643'
  tag rid: 'SV-68889r1_rule'
  tag stig_id: 'SRG-NET-000370-ALG-000125'
  tag gtitle: 'SRG-NET-000370-ALG-000125'
  tag fix_id: 'F-59499r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002400']
  tag nist: ['SC-7 (9) (b)']
end
