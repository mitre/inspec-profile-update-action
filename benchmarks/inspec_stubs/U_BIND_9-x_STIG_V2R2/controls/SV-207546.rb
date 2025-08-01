control 'SV-207546' do
  title 'The BIND 9.x server implementation must be configured with a channel to send audit records to a remote syslog.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on a defined frequency helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', 'Verify that the BIND 9.x server is configured to send audit logs to the syslog service.

NOTE: syslog and local file channel must be defined for every defined category.

Inspect the "named.conf" file for the following:

logging {
channel <syslog_channel> {
syslog <syslog_facility>;
};

category <category_name> { <syslog_channel>; };

If a logging channel is not defined for syslog, this is a finding.

If a category is not defined to send messages to the syslog channel, this is a finding.

Ensure audit records are forwarded to a remote server:

# grep "\\*.\\*" /etc/syslog.conf |grep "@" | grep -v "^#" (for syslog)
or:
# grep "\\*.\\*" /etc/rsyslog.conf | grep "@" | grep -v "^#" (for rsyslog)

If neither of these lines exist, this is a finding.'
  desc 'fix', 'Configure the "logging" statement to send audit logs to the syslog daemon.

logging {
channel <syslog_channel> {
syslog <syslog_facility>;
};
category <category_name> { <syslog_channel>; };
};

Note: It is recommended to use a local syslog facility (i.e. local0 -7) when configuring the syslog channel. 

Restart the BIND 9.x process.

Configure the (r)syslog daemon to send audit logs to a remote server.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7801r744224_chk'
  tag severity: 'low'
  tag gid: 'V-207546'
  tag rid: 'SV-207546r744225_rule'
  tag stig_id: 'BIND-9X-001040'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-7801r283693_fix'
  tag 'documentable'
  tag legacy: ['SV-87015', 'V-72391']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
