control 'SV-86149' do
  title 'The CA API Gateway must forward all log audit log messages to the central log server.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', 'Verify the CA API Gateway forwards all log audit log messages to the central log server. 

Within the "/etc/rsyslog.conf" file, confirm a rule in the format "*.* @@loghost.log.com" is in the ruleset section.

If the CA API Gateway "/etc/rsyslog.conf" file does not have a rule in the format "*.* @@loghost.log.com" in the ruleset section, this is a finding.'
  desc 'fix', 'Configure the CA API Gateway to forward all audit log messages to the central log server.

- Log in to CA API Gateway as root.
- Open "/etc/rsyslog.conf" for editing.
- Add a rule "*.* @@loghost.log.com" to the ruleset section of the "rsyslogd.conf" file.'
  impact 0.3
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71897r1_chk'
  tag severity: 'low'
  tag gid: 'V-71525'
  tag rid: 'SV-86149r1_rule'
  tag stig_id: 'CAGW-DM-000130'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-77845r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
