control 'SV-228839' do
  title 'The Palo Alto Networks security platform must not enable the DNS proxy.'
  desc 'The Palo Alto Networks security platform can act as a DNS proxy and send the DNS queries on behalf of the clients. DNS queries that arrive on an interface IP address can be directed to different DNS servers based on full or partial domain names.

However, unrelated or unneeded proxy services increase the attack vector surface and add excessive complexity to securing the device.'
  desc 'check', 'To check if DNS Proxy is configured:
Go to Network >> DNS Proxy
If there are entries in the pane, this is a finding.'
  desc 'fix', 'Do not configure and enable the DNS Proxy capability.

Go to Network >> DNS Proxy
If there are no entries in the pane, then this capability has not been enabled.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31074r513812_chk'
  tag severity: 'medium'
  tag gid: 'V-228839'
  tag rid: 'SV-228839r557387_rule'
  tag stig_id: 'PANW-AG-000037'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-31051r513813_fix'
  tag 'documentable'
  tag legacy: ['V-62561', 'SV-77051']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
