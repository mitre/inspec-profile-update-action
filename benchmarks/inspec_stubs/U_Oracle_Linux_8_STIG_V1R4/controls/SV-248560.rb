control 'SV-248560' do
  title 'The OL 8 SSH daemon must be configured to use system-wide crypto policies.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

OL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.'
  desc 'check', 'Verify that system-wide crypto policies are in effect:

$ sudo grep -i CRYPTO_POLICY /etc/sysconfig/sshd

# CRYPTO_POLICY=

If the "CRYPTO_POLICY" is uncommented, this is a finding.'
  desc 'fix', 'Configure the OL 8 SSH daemon to use system-wide crypto policies by adding the following line to /etc/sysconfig/sshd:

# CRYPTO_POLICY=

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51994r818612_chk'
  tag severity: 'medium'
  tag gid: 'V-248560'
  tag rid: 'SV-248560r818614_rule'
  tag stig_id: 'OL08-00-010287'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-51948r818613_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
