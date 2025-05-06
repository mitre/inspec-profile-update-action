control 'SV-237948' do
  title 'The IBM z/VM TCP/IP SECURETELNETCLIENT option for telnet must be set to YES.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPsec.

The SECUREDATA statement specifies the FTP server-wide minimum security level for data connections.'
  desc 'check', 'Examine the TCP/IP DATA file.

If "SECURETELNETCLIENT" option is set to "YES", this is not a finding.'
  desc 'fix', 'Configure the TCP/IP DATA file "SECURETELNETCLIENT" option to "YES".'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41158r859024_chk'
  tag severity: 'medium'
  tag gid: 'V-237948'
  tag rid: 'SV-237948r859026_rule'
  tag stig_id: 'IBMZ-VM-001090'
  tag gtitle: 'SRG-OS-000426-GPOS-00190'
  tag fix_id: 'F-41117r859025_fix'
  tag 'documentable'
  tag legacy: ['SV-93649', 'V-78943']
  tag cci: ['CCI-002452']
  tag nist: ['SC-15 (4)']
end
