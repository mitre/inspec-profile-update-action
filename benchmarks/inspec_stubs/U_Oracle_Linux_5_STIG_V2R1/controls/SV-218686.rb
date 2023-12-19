control 'SV-218686' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20161r556475_chk'
  tag severity: 'medium'
  tag gid: 'V-218686'
  tag rid: 'SV-218686r603259_rule'
  tag stig_id: 'GEN007850'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20159r556476_fix'
  tag 'documentable'
  tag legacy: ['V-22549', 'SV-63409']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
