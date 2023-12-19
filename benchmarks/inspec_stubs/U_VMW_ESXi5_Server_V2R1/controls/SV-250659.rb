control 'SV-250659' do
  title 'The system must enable bidirectional CHAP authentication for iSCSI traffic.'
  desc 'When enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. There is a potential for a MiTM attack, when not authenticating both the iSCSI target and host, in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc 'check', 'This check applies to the use of iSCSI storage. If iSCSI storage is not used, this check is not applicable. 

In the vSphere Client, select the host, and then choose: Configuration - Storage Adaptors - iSCSI Initiator Properties -  CHAP - CHAP (Target Authenticates Host) - determine if "Use Chap" is selected with a "Name" and a "Secret" configured.

If iSCSI storage is used and "Use CHAP" is not selected and configured with a "Name" and a "Secret", this is a finding.'
  desc 'fix', 'In the vSphere Client, select the host, and then choose: Configuration >> Storage Adaptors >> iSCSI Initiator Properties >>  CHAP >> CHAP (Target Authenticates Host). Select "Use Chap", and configure the "Name" and "Secret" options.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54094r798974_chk'
  tag severity: 'low'
  tag gid: 'V-250659'
  tag rid: 'SV-250659r798976_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000141'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54048r798975_fix'
  tag 'documentable'
  tag legacy: ['V-39298', 'SV-51114']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
