control 'SV-206685' do
  title 'The firewall must be configured to use TCP when sending log records to the central audit server.'
  desc 'If the default UDP protocol is used for communication between the hosts and devices to the Central Log Server, then log records that do not reach the log server are not detected as a data loss. The use of TCP to transport log records to the log servers improves delivery reliability.'
  desc 'check', 'Review the firewall configuration and verify that it is configure to use TCP.


If the firewall is not configured to use TCP when sending log records to the central audit server, this is a finding.'
  desc 'fix', 'Configure the firewall to use TCP when sending log records to the central audit server.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6942r457833_chk'
  tag severity: 'medium'
  tag gid: 'V-206685'
  tag rid: 'SV-206685r604133_rule'
  tag stig_id: 'SRG-NET-000098-FW-000021'
  tag gtitle: 'SRG-NET-000098'
  tag fix_id: 'F-6942r457834_fix'
  tag 'documentable'
  tag legacy: ['V-79453', 'SV-94159']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
