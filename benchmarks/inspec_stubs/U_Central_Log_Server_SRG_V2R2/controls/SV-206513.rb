control 'SV-206513' do
  title 'The Central Log Server that aggregates log records from hosts and devices must be configured to use TCP for transmission.'
  desc 'If the default UDP protocol is used for communication between the hosts and devices to the Central Log Server, then log records that do not reach the log server are not detected as a data loss. The use of TCP to transport log records to the log servers improves delivery reliability, adds data integrity, and gives the option to encrypt the traffic if the log server communication is not protected using a management network (preferred) or VPN based on mission requirements.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to use TCP.

If the Central Log Server is not configured to use TCP, this is a finding.'
  desc 'fix', 'Configure the Central Log Server that aggregates log records from hosts and devices to use TCP for transmission.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6773r285780_chk'
  tag severity: 'medium'
  tag gid: 'V-206513'
  tag rid: 'SV-206513r401224_rule'
  tag stig_id: 'SRG-APP-000516-AU-000340'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-6773r285781_fix'
  tag 'documentable'
  tag legacy: ['SV-95895', 'V-81181']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
