control 'SV-254103' do
  title 'Nutanix AOS must offload log records onto a syslog server.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Offloading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to offload log records onto a different system or media than the system being logged.

'
  desc 'check', 'Confirm Nutanix AOS is configured to offload log records onto a different system. 

$ ncli rsyslog-config ls-servers

If no remote syslog servers are defined, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to offload log records onto a different system by running the following command.

$ ncli rsyslog-config add-server name=<remote_server_name> relp-enabled=<true | false> ip-address=<remote_ip_address> port=<port_num> network-protocol=<tcp | udp>'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57588r846395_chk'
  tag severity: 'medium'
  tag gid: 'V-254103'
  tag rid: 'SV-254103r846397_rule'
  tag stig_id: 'NUTX-AP-000110'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag fix_id: 'F-57539r846396_fix'
  tag satisfies: ['SRG-APP-000080-AS-000045', 'SRG-APP-000358-AS-000064', 'SRG-APP-000515-AS-000203']
  tag 'documentable'
  tag cci: ['CCI-000166', 'CCI-001851']
  tag nist: ['AU-10', 'AU-4 (1)']
end
