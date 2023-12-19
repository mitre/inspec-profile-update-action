control 'SV-203749' do
  title 'The operating system must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes. 

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to leverage transmission protection mechanisms such as TLS, SSL VPNs, or IPSec.

Alternative physical protection measures include PDS. PDSs are used to transmit unencrypted classified National Security Information (NSI) through an area of lesser classification or control. Since the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation.'
  desc 'check', 'Verify the operating system implements cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a  minimum, a Protected Distribution System (PDS). 

If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  impact 0.7
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3874r877464_chk'
  tag severity: 'high'
  tag gid: 'V-203749'
  tag rid: 'SV-203749r877465_rule'
  tag stig_id: 'SRG-OS-000424-GPOS-00188'
  tag gtitle: 'SRG-OS-000424'
  tag fix_id: 'F-3874r877029_fix'
  tag 'documentable'
  tag legacy: ['V-56733', 'SV-70993']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
