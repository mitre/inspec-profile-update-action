control 'SV-26933' do
  title 'The DHCP client must not send dynamic DNS updates.'
  desc 'Dynamic DNS updates transmit unencrypted information about a system including its name and address and should not be used unless needed.'
  desc 'check', 'If the "dhclient" package is not installed, this is not applicable.

Verify the DHCP client is configured to not send dynamic DNS updates.

Procedure:
# grep do-forward-updates /etc/dhclient.conf

If the file is not present, does not contain this configuration, or has the setting set to "true", this is a finding.'
  desc 'fix', 'Edit or add the "/etc/dhclient.conf" file and add or edit the "do-forward-updates" setting to false.

Procedure:
# echo "do-forward-updates false;" >> /etc/dhclient.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27883r2_chk'
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
