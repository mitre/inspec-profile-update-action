control 'SV-213516' do
  title 'JBoss log records must be off-loaded onto a different system or system component a minimum of every seven days.'
  desc 'JBoss logs by default are written to the local file system.  A centralized logging solution like syslog should be used whenever possible; however, any log data stored to the file system needs to be off-loaded.  JBoss EAP does not provide an automated backup capability.  Instead, reliance is placed on OS or third-party tools to back up or off-load the log files.

Protection of log data includes assuring log data is not accidentally lost or deleted. Off-loading log records to a different system or onto separate media from the system the application server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Interview the system admin and obtain details on how the log files are being off-loaded to a different system or media.

If the log files are not off-loaded a minimum of every 7 days, this is a finding.'
  desc 'fix', 'Configure the application server to off-load log records every seven days onto a different system or media from the system being logged.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14739r296214_chk'
  tag severity: 'medium'
  tag gid: 'V-213516'
  tag rid: 'SV-213516r615939_rule'
  tag stig_id: 'JBOS-AS-000195'
  tag gtitle: 'SRG-APP-000125-AS-000084'
  tag fix_id: 'F-14737r296215_fix'
  tag 'documentable'
  tag legacy: ['SV-76747', 'V-62257']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
