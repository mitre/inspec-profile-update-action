control 'SV-26933' do
  title 'The DHCP client must not send dynamic DNS updates.'
  desc 'Dynamic DNS updates transmit unencrypted information about a system including its name and address and should not be used unless needed.'
  desc 'fix', 'Edit or add the "/etc/dhclient.conf" file and add or edit the "do-forward-updates" setting to false.

Procedure:
# echo "do-forward-updates false;" >> /etc/dhclient.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22549'
  tag rid: 'SV-26933r2_rule'
  tag stig_id: 'GEN007850'
  tag gtitle: 'GEN007850'
  tag fix_id: 'F-24178r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
