control 'SV-251373' do
  title 'A centralized syslog server must be deployed in the management network.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, understand past intrusions, troubleshoot service disruptions, and react to probes and scans of the network.'
  desc 'check', 'Review the network topology and verify that a syslog server is located within the management network. Note the IP address as documented on the management network topology and verify that this is what is configured on the network elements as the host device for sending syslog data.

If a centralized syslog server has not been deployed in the management network, this is a finding.'
  desc 'fix', 'Stand up a syslog server and connect it to the management network. Configure all managed network elements to send syslog data to the syslog server.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54808r806072_chk'
  tag severity: 'low'
  tag gid: 'V-251373'
  tag rid: 'SV-251373r806074_rule'
  tag stig_id: 'NET1025'
  tag gtitle: 'NET1025'
  tag fix_id: 'F-54761r806073_fix'
  tag 'documentable'
  tag legacy: ['V-8060', 'SV-8546']
  tag cci: ['CCI-001575']
  tag nist: ['AU-9 (2)']
end
