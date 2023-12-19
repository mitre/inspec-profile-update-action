control 'SV-207551' do
  title 'The BIND 9.x server implementation must limit the number of concurrent session client connections to the number of allowed dynamic update clients.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation. 

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements."
  desc 'check', 'Verify the name server is configured to limit the number of concurrent client connections to the number of allowed dynamic update clients:

Inspect the "named.conf" file for the following:

options {
transfers-out 10;
};

If the "options" statement does not contain a "transfers-out" sub statement, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "transfers-out" sub statement to the "options" statement block.

The value of the "transfers-out" will be based on organizational requirements needed to support DNS operations.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7806r283707_chk'
  tag severity: 'medium'
  tag gid: 'V-207551'
  tag rid: 'SV-207551r612253_rule'
  tag stig_id: 'BIND-9X-001052'
  tag gtitle: 'SRG-APP-000001-DNS-000115'
  tag fix_id: 'F-7806r283708_fix'
  tag 'documentable'
  tag legacy: ['SV-87025', 'V-72401']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
