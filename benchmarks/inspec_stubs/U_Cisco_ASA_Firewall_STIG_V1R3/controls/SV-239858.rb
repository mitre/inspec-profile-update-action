control 'SV-239858' do
  title 'The Cisco ASA must be configured to use TCP when sending log records to the central audit server.'
  desc 'If the default UDP protocol is used for communication between the hosts and devices to the Central Log Server, then log records that do not reach the log server are not detected as a data loss. The use of TCP to transport log records to the log servers improves delivery reliability.'
  desc 'check', 'Review the ASA configuration and verify it is configured to use TCP as shown in the example below.

logging host NDM_INTERFACE 10.1.22.2 6/1514
logging permit-hostdown

Note: The command "logging permit-hostdown" must also be configured to ensure that when either the syslog server is down or the log queue is full, new connections to ASA are allowed, to prevent an unintended denial of service. However, log records can be lost if the internal queue fills before restoring the connection to the log server.

If the ASA is not configured to use TCP when sending log records to the central audit server, this is a finding.'
  desc 'fix', 'Configure the ASA to use TCP when sending log records to the syslog server.

ASA(config)# logging host NDM_INTERFACE 10.1.22.2 6/1514
ASA(config)# logging permit-hostdown'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43091r819135_chk'
  tag severity: 'medium'
  tag gid: 'V-239858'
  tag rid: 'SV-239858r819136_rule'
  tag stig_id: 'CASA-FW-000100'
  tag gtitle: 'SRG-NET-000098-FW-000021'
  tag fix_id: 'F-43050r665859_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
