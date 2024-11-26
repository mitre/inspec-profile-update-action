control 'SV-237947' do
  title 'All IBM z/VM TCP/IP servers must be configured for SSL/TLS connection.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPsec.'
  desc 'check', 'Determine SSL/TLS capability.

Examine the TCP/IP config file.

If the “SSLSERVERID” statement identifies at least one userID for SSL server, this is not a finding.'
  desc 'fix', 'Configure the “SSLSERVERID” statement to force auto logging of an SSL server before all other servers in the “AUTOLOG” list.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41157r649679_chk'
  tag severity: 'medium'
  tag gid: 'V-237947'
  tag rid: 'SV-237947r649681_rule'
  tag stig_id: 'IBMZ-VM-001070'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-41116r649680_fix'
  tag 'documentable'
  tag legacy: ['SV-93647', 'V-78941']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
