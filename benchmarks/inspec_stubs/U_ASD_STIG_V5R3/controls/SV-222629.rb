control 'SV-222629' do
  title 'The application must be registered with the DoD Ports and Protocols Database.'
  desc 'Failure to register the applications usage of ports, protocols, and services with the DoD PPS Database may result in a Denial of Service (DoS) because of enclave boundary protections at other end points within the network.'
  desc 'check', 'Verify registration of the application and ports in the Ports and Protocols Database for a production site.

If the application requires registration, and is not registered or all ports used have not been identified in the database, this is a finding.'
  desc 'fix', 'Register the application and ports in the Ports and Protocols Database.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24299r493795_chk'
  tag severity: 'medium'
  tag gid: 'V-222629'
  tag rid: 'SV-222629r879887_rule'
  tag stig_id: 'APSC-DV-002990'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24288r493796_fix'
  tag 'documentable'
  tag legacy: ['SV-84939', 'V-70317']
  tag cci: ['CCI-000388']
  tag nist: ['CM-7 (3)']
end
