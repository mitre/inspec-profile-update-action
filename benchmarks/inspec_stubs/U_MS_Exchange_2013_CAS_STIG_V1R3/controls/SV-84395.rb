control 'SV-84395' do
  title 'Exchange must provide redundancy.'
  desc 'Load balancing is a way to manage which Exchange servers receive traffic. Load balancing helps distribute incoming client connections over a variety of endpoints. This ensures that no one endpoint takes on a disproportional share of the load. Load balancing provides failover redundancy in case one or more endpoints fails. By using load balancing, users continue to receive Exchange service in case of a computer failure. Load balancing also enables Exchange to handle more traffic than one server can process while offering a single host name for your clients.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine if the Exchange Servers are using redundancy.

Get-ClientAccessServer | Select Name, Site

If the value returned is not at least two CAS servers, this is a finding.'
  desc 'fix', 'Update the EDSP.

Configure two or more CAS servers for load balancing.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70223r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69773'
  tag rid: 'SV-84395r1_rule'
  tag stig_id: 'EX13-CA-000145'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-75985r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
