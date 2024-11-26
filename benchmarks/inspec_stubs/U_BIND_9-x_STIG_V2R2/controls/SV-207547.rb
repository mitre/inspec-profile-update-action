control 'SV-207547' do
  title 'The BIND 9.x server implementation must be configured with a channel to send audit records to a local file.'
  desc 'DNS software administrators require DNS transaction logs for a wide variety of reasons including troubleshooting, intrusion detection, and forensics. Ensuring that the DNS transaction logs are recorded on the local system will provide the capability needed to support these actions.'
  desc 'check', 'Verify that the BIND 9.x server is configured to send audit logs to a local log file.

NOTE: syslog and local file channel must be defined for every defined category.

Inspect the "named.conf" file for the following:

logging {
channel local_file_channel {
file "path_name" versions 3;
print-time yes;
print-severity yes;
print-category yes;
};

category category_name { local_file_channel; };

If a logging channel is not defined for a local file, this is a finding.

If a category is not defined to send messages to the local file channel, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file and add the following:

logging {
channel local_file_channel {
file "path_name" versions 3;
print-time yes;
print-severity yes;
print-category yes;
};
category category_name { local_file_channel; };
};

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7802r744226_chk'
  tag severity: 'low'
  tag gid: 'V-207547'
  tag rid: 'SV-207547r744227_rule'
  tag stig_id: 'BIND-9X-001041'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-7802r283696_fix'
  tag 'documentable'
  tag legacy: ['SV-87017', 'V-72393']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
