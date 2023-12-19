control 'SV-233086' do
  title 'The container platform must uniquely identify all network-connected nodes before establishing any connection.'
  desc 'A container platform usually consists of multiple nodes. It is important for these nodes to be uniquely identified before a connection is allowed. Without identifying the nodes, unidentified or unknown nodes may be introduced, thereby facilitating malicious activity.'
  desc 'check', 'Review the container platform configuration to determine if the container platform uniquely identifies all nodes before establishing a connection. 

If the container platform is not configured to uniquely identify all nodes before establishing the connection, this is a finding.'
  desc 'fix', 'Configure the container platform to uniquely identify all nodes before establishing the connection.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36022r599576_chk'
  tag severity: 'medium'
  tag gid: 'V-233086'
  tag rid: 'SV-233086r599577_rule'
  tag stig_id: 'SRG-APP-000158-CTR-000390'
  tag gtitle: 'SRG-APP-000158'
  tag fix_id: 'F-35990r598895_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
