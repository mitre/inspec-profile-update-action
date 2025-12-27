control 'SV-207549' do
  title 'The BIND 9.x secondary name server must limit the number of zones requested from a single master name server.'
  desc "Limiting the number of concurrent sessions reduces the risk of Denial of Service (DoS) to the DNS implementation.

Name servers do not have direct user connections but accept client connections for queries. Original restriction on client connections should be high enough to prevent a self-imposed denial of service, after which the connections are monitored and fine-tuned to best meet the organization's specific requirements."
  desc 'check', 'If this is not a secondary name server, this requirement is Not Applicable.

Verify that the secondary name server is configured to limit the number of zones requested from a single master name server.

Inspect the "named.conf" file for the following:

options {
transfers-per-ns 2;
};

If the "options" statement does not contain a "transfers-per-ns" sub statement, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "transfers-per-ns" sub statement to the "options" statement block.

The value of the "transfers-per-ns" option can be increased to a value greater than two based on organizational requirements needed to support DNS operations.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7804r283701_chk'
  tag severity: 'medium'
  tag gid: 'V-207549'
  tag rid: 'SV-207549r612253_rule'
  tag stig_id: 'BIND-9X-001050'
  tag gtitle: 'SRG-APP-000001-DNS-000001'
  tag fix_id: 'F-7804r283702_fix'
  tag 'documentable'
  tag legacy: ['SV-87021', 'V-72397']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
