control 'SV-70989' do
  title 'The operating system must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, operating systems need to leverage protection mechanisms such as TLS, SSL VPNs, or IPSec.'
  desc 'check', 'Verify the operating system maintains the confidentiality and integrity of information during reception. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to maintain the confidentiality and integrity of information during reception.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56729'
  tag rid: 'SV-70989r1_rule'
  tag stig_id: 'SRG-OS-000426-GPOS-00190'
  tag gtitle: 'SRG-OS-000426-GPOS-00190'
  tag fix_id: 'F-61625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
