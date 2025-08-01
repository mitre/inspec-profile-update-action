control 'SV-207540' do
  title 'The BIND 9.x server implementation must not be configured with a channel to send audit records to null.'
  desc 'DNS software administrators require DNS transaction logs for a wide variety of reasons including troubleshooting, intrusion detection, and forensics. Ensuring that the DNS transaction logs are recorded on the local system will provide the capability needed to support these actions. Sending DNS transaction data to the null channel would cause a loss of important data.'
  desc 'check', 'Verify that the BIND 9.x server is not configured to send audit logs to the null channel.

Inspect the "named.conf" file for the following:

category null { null; }

If there is a category defined to send audit logs to the "null" channel, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Remove any instance of the following:

category null { null; };

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7795r283674_chk'
  tag severity: 'low'
  tag gid: 'V-207540'
  tag rid: 'SV-207540r612253_rule'
  tag stig_id: 'BIND-9X-001017'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-7795r283675_fix'
  tag 'documentable'
  tag legacy: ['SV-87003', 'V-72379']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
