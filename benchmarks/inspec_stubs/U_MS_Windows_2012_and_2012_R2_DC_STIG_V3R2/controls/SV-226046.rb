control 'SV-226046' do
  title 'Protection methods such as TLS, encrypted VPNs, or IPSEC must be implemented if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking.  These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, encrypted VPNs, or IPSEC.'
  desc 'check', 'If the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, verify protection methods such as TLS, encrypted VPNs, or IPSEC have been implemented.  If protection methods have not been implemented, this is a finding.'
  desc 'fix', 'Configure protection methods such as TLS, encrypted VPNs, or IPSEC when the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process to maintain the confidentiality and integrity.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27748r475461_chk'
  tag severity: 'medium'
  tag gid: 'V-226046'
  tag rid: 'SV-226046r569184_rule'
  tag stig_id: 'WN12-00-000019'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-27736r475462_fix'
  tag 'documentable'
  tag legacy: ['SV-72051', 'V-57641']
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
