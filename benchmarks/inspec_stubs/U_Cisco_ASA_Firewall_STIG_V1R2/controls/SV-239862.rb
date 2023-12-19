control 'SV-239862' do
  title 'The Cisco ASA must be configured to send log data of denied traffic to a central audit server for analysis.'
  desc 'Without the ability to centrally manage the content captured in the traffic log entries, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized traffic log management must have the ability to support centralized management. The content captured in traffic log entries must be managed from a central location (necessitating automation). Centralized management of traffic log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. 

Ensure at least one syslog server is configured on the firewall.'
  desc 'check', 'Verify that the ASA is configured to send logs to a syslog server. The configuration should look similar to the example below.

logging trap notifications
logging host NDM_INTERFACE 10.1.48.10/1514

If the ASA is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the ASA to send log messages to the syslog server as shown in the example below.

ASA(config)# logging host NDM_INTERFACE 10.1.48.10/1514
ASA(config)# logging trap notifications 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43095r665870_chk'
  tag severity: 'medium'
  tag gid: 'V-239862'
  tag rid: 'SV-239862r819162_rule'
  tag stig_id: 'CASA-FW-000200'
  tag gtitle: 'SRG-NET-000333-FW-000014'
  tag fix_id: 'F-43054r665871_fix'
  tag 'documentable'
  tag cci: ['CCI-001821']
  tag nist: ['CM-1 a 1 (a)']
end
