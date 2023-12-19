control 'SV-235997' do
  title 'Oracle WebLogic must be integrated with a tool to monitor audit subsystem failure notification information that is sent out (e.g., the recipients of the message and the nature of the failure).'
  desc 'It is critical that, when a system is at risk of failing to process audit logs, it detects and takes action to mitigate the failure. As part of the mitigation, the system must send a notification to designated individuals that auditing is failing, log the notification message and the individuals who received the notification. When the system is not capable of notification and notification logging, an external software package, such as Oracle Diagnostic Framework, must be used.'
  desc 'check', 'Review the configuration of Oracle WebLogic to determine if a tool, such as Oracle Diagnostic Framework, is in place to monitor audit subsystem failure notification information that is sent out. 

If a tool is not in place to monitor audit subsystem failure notification information that is sent, this is a finding.'
  desc 'fix', 'Install a tool, such as Oracle Diagnostics Framework, to monitor audit subsystem failure notification information.'
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39216r628767_chk'
  tag severity: 'medium'
  tag gid: 'V-235997'
  tag rid: 'SV-235997r628769_rule'
  tag stig_id: 'WBLC-10-000270'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39179r628768_fix'
  tag 'documentable'
  tag legacy: ['SV-70637', 'V-56383']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
