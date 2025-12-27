control 'SV-16728' do
  title 'CHAP authentication is not configured for iSCSI traffic.'
  desc 'ISCSI connections are able to be configured with Challenge Handshake Authentication Protocol (CHAP) authentication and IP security (IPSec) encryption. “ESX Server only supports one-way CHAP authentication for iSCSI. It does not support Kerberos, Secure Remote Protocol (SRP), IPSec, or public key authentication methods for iSCSI authentication.” For both software and hardware iSCSI initiators, configuring CHAP for iSCSI connections will ensure proper authentication. “After the iSCSI initiator establishes the initial connection with the target, CHAP verifies the identity of the initiator and checks a CHAP secret that the initiator and the target share. This can be repeated periodically during the iSCSI session.”'
  desc 'check', 'To check the authentication method, perform the following within VirtualCenter:

1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
2. Click the Configuration tab and click Storage Adapters.
3. Select the iSCSI adapter to check and click the Properties to open the iSCSI Initiator Properties dialog box.
4. Click CHAP Authentication. If the CHAP Name shows a name, often the iSCSI initiator name, the iSCSI SAN is using CHAP authentication, and this is Not a Finding.  
5. If the CHAP Name shows Not Specified, then the iSCSI SAN is not using CHAP authentication, and this is a finding.'
  desc 'fix', 'Enable CHAP authentication for iSCSI SAN connections.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-15976r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15789'
  tag rid: 'SV-16728r1_rule'
  tag stig_id: 'ESX0070'
  tag gtitle: 'No CHAP authentication for iSCSI traffic.'
  tag fix_id: 'F-15731r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
