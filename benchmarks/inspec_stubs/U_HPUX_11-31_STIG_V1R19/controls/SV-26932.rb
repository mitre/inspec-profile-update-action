control 'SV-26932' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'check', %q(Check the DHCP_ENABLE setting in /etc/rc.config.d/netconf
# /etc/rc.config.d/netconf| tr '\011' ' ' | tr -s ' ' | \
sed -e 's/^[ \t]*//' | grep -v "^#" |grep "DHCP_ENABLE"

If the setting is set to 1, this is a finding.)
  desc 'fix', 'Disable the DHCP client configuration.
Edit /etc/rc.config.d/netconf and set the DHCP_ENABLE setting to 0.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22548'
  tag rid: 'SV-26932r1_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'GEN007840'
  tag fix_id: 'F-24175r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
