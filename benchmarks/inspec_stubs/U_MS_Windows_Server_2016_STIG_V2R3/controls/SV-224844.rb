control 'SV-224844' do
  title 'Protection methods such as TLS, encrypted VPNs, or IPsec must be implemented if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, encrypted VPNs, or IPsec.

'
  desc 'check', 'If the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, verify protection methods such as TLS, encrypted VPNs, or IPsec have been implemented.

If protection methods have not been implemented, this is a finding.'
  desc 'fix', 'Configure protection methods such as TLS, encrypted VPNs, or IPsec when the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26535r465434_chk'
  tag severity: 'medium'
  tag gid: 'V-224844'
  tag rid: 'SV-224844r790513_rule'
  tag stig_id: 'WN16-00-000290'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-26523r465435_fix'
  tag satisfies: ['SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag legacy: ['SV-87927', 'V-73275']
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
