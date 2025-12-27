control 'SV-207418' do
  title 'The VMM must implement cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic VMMs by an authorized user (or another VMM) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Verify the VMM implements cryptography to protect the integrity of remote access sessions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement cryptography to protect the integrity of remote access sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7675r365664_chk'
  tag severity: 'medium'
  tag gid: 'V-207418'
  tag rid: 'SV-207418r379225_rule'
  tag stig_id: 'SRG-OS-000250-VMM-000860'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-7675r365665_fix'
  tag 'documentable'
  tag legacy: ['V-57037', 'SV-71297']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
