control 'SV-207550' do
  title 'The BIND 9.x secondary name server must limit the total number of zones the name server can request at any one time.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation.

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements."
  desc 'check', 'If this is not a secondary name server, this requirement is Not Applicable.

Verify the name server is configured to limit the total number of zones that can be requested at one time:

Inspect the "named.conf" file for the following:

options {
transfers-in 10;
};

If the "options" statement does not contain a "transfers-in" sub statement, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "transfers-in" sub statement to the "options" statement block.

The value of the "transfers-in" will be based on organizational requirements needed to support DNS operations.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7805r283704_chk'
  tag severity: 'medium'
  tag gid: 'V-207550'
  tag rid: 'SV-207550r612253_rule'
  tag stig_id: 'BIND-9X-001051'
  tag gtitle: 'SRG-APP-000001-DNS-000001'
  tag fix_id: 'F-7805r283705_fix'
  tag 'documentable'
  tag legacy: ['SV-87023', 'V-72399']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
