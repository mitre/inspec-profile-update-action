control 'SV-45988' do
  title 'The DHCP client must not send dynamic DNS updates.'
  desc 'Dynamic DNS updates transmit unencrypted information about a system including its name and address and should not be used unless needed.'
  desc 'check', 'If the "dhcp-client" package is not installed, this is not applicable.

Verify the DHCP client is configured to not send dynamic DNS updates.

Procedure:
# rpm –q dhcp-client   
If DHCP client is found then issue following command to determine if the DHCP client sends dynamic DNS updates:

# grep do-forward-updates /etc/dhclient.conf

If the DHCP client is installed and the configuration file is not present, or contains do-forward-updates = “true”, then this is a finding'
  desc 'fix', 'Edit or add the "/etc/dhclient.conf" file and add or edit the "do-forward-updates" setting to false.

Procedure:
# echo "do-forward-updates false;" >> /etc/dhclient.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43270r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22549'
  tag rid: 'SV-45988r2_rule'
  tag stig_id: 'GEN007850'
  tag gtitle: 'GEN007850'
  tag fix_id: 'F-39353r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
