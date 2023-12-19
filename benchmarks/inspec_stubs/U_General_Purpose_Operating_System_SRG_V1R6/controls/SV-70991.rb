control 'SV-70991' do
  title 'The operating system must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPSec.'
  desc 'check', 'Verify the operating system maintains the confidentiality and integrity of information during preparation for transmission. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to maintain the confidentiality and integrity of information during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56731'
  tag rid: 'SV-70991r1_rule'
  tag stig_id: 'SRG-OS-000425-GPOS-00189'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-61627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
