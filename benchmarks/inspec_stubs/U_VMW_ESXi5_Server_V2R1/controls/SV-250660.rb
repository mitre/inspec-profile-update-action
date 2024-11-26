control 'SV-250660' do
  title 'The system must enable SSL for NFC.'
  desc 'NFC (Network File Copy) is used to migrate or clone a VM between two ESXi hosts over the network. By default, SSL is used only for the authentication of the transfer, but SSL must also be enabled on the data transfer. Without this setting VM contents could potentially be sniffed if the management network is not adequately isolated and secured.'
  desc 'check', 'NOTE: SSL for NFC is used for copying or migrating VMs between ESXi hosts via vCenter. If the host is a standalone unit (i.e., not managed by a vCenter Server), this check is not applicable.

From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Verify "config.nfc.useSSL" is set to true.

If "config.nfc.useSSL" is set to false, this is a finding.'
  desc 'fix', 'From the vSphere client select "Administration >> vCenter Server Settings >> Advanced Settings". Set "config.nfc.useSSL = true".'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54095r798977_chk'
  tag severity: 'low'
  tag gid: 'V-250660'
  tag rid: 'SV-250660r798979_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000143'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54049r798978_fix'
  tag 'documentable'
  tag legacy: ['SV-51115', 'V-39299']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
