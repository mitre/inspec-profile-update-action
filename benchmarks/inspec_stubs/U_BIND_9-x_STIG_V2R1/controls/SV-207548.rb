control 'SV-207548' do
  title 'The BIND 9.x server implementation must maintain at least 3 file versions of the local log file.'
  desc 'DNS software administrators require DNS transaction logs for a wide variety of reasons including troubleshooting, intrusion detection, and forensics. Ensuring that the DNS transaction logs are recorded on the local system will provide the capability needed to support these actions.'
  desc 'check', 'Verify that the BIND 9.x server is configured to retain at least 3 versions of the local log file.

Inspect the "named.conf" file for the following:

logging {
channel local_file_channel {
file "path_name" versions 3;
};

If the "versions" variable is not defined, this is a finding.

If the "versions" variable is configured to retain less than 3 versions of the local log file, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "versions" variable to the end of the "file" sub statement in the channel statement.

Configure the "versions" sub statement to a number that is greater or equal to 3.

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7803r283698_chk'
  tag severity: 'low'
  tag gid: 'V-207548'
  tag rid: 'SV-207548r612253_rule'
  tag stig_id: 'BIND-9X-001042'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-7803r283699_fix'
  tag 'documentable'
  tag legacy: ['SV-87019', 'V-72395']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
