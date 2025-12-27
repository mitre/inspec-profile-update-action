control 'SV-5611' do
  title 'The network devices must only allow management connections for administrative access from hosts residing in the management network.'
  desc 'Remote administration is inherently dangerous because anyone with a sniffer and access to the right LAN segment could acquire the device account and password information. With this intercepted information they could gain access to the infrastructure and cause denial of service attacks, intercept sensitive information, or perform other destructive actions.'
  desc 'check', 'Review the configuration and verify management access to the device is allowed only from hosts within the management network.

If management access can be gained from outside of the authorized management network, this is a finding.'
  desc 'fix', 'Configure an ACL or filter to restrict management access to the device from only the management network.'
  impact 0.5
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-3527r6_chk'
  tag severity: 'medium'
  tag gid: 'V-5611'
  tag rid: 'SV-5611r5_rule'
  tag stig_id: 'NET1637'
  tag gtitle: 'Management connections are not restricted.'
  tag fix_id: 'F-5522r4_fix'
  tag 'documentable'
end
