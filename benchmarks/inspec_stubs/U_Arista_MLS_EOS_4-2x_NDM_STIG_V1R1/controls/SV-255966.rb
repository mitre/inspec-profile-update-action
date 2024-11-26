control 'SV-255966' do
  title 'The Arista network Arista device must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.

'
  desc 'check', 'Verify the Arista network device has been configured Syslog server for auditing data by using the following command:

switch#show running-config | section logging

logging host 192.168.16.30 514
!

If logging host is not configured to send log data to a central log server, this is a finding.'
  desc 'fix', 'The Arista network device must be configured for Syslog server for auditing data by using the following commands:

switch(config)#logging host 192.168.16.30 514'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59642r882238_chk'
  tag severity: 'high'
  tag gid: 'V-255966'
  tag rid: 'SV-255966r882240_rule'
  tag stig_id: 'ARST-ND-000850'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-59585r882239_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000350', 'SRG-APP-000119-NDM-000236', 'SRG-APP-000120-NDM-000237', 'SRG-APP-000515-NDM-000325']
  tag 'documentable'
  tag cci: ['CCI-000163', 'CCI-000164', 'CCI-001851']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-4 (1)']
end
