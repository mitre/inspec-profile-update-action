control 'SV-203669' do
  title 'The operating system must implement cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Verify the operating system implements cryptography to protect the integrity of remote access sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptography to protect the integrity of remote access sessions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3794r374834_chk'
  tag severity: 'medium'
  tag gid: 'V-203669'
  tag rid: 'SV-203669r379225_rule'
  tag stig_id: 'SRG-OS-000250-GPOS-00093'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-3794r374835_fix'
  tag 'documentable'
  tag legacy: ['V-56935', 'SV-71195']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
