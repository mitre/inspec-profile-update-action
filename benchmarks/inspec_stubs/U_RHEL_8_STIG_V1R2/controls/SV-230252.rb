control 'SV-230252' do
  title 'The RHEL 8 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.

By specifying a cipher list with the order of ciphers being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.

'
  desc 'check', %q(Verify the SSH daemon is configured to use only ciphers employing FIPS 140-2-approved algorithms:

Verify that system-wide crypto policies are in effect:

$ sudo grep -i crypto_policy /etc/sysconfig/sshd

# crypto_policy=

If the "crypto_policy" is uncommented, this is a finding.

Verify which system-wide crypto policy is in use:

$ sudo update-crypto-policies --show

FIPS

Check that the ciphers in the back-end configurations are FIPS 140-2-approved algorithms with the following command:

$ sudo grep -i ciphers /etc/crypto-policies/back-ends/openssh.config /etc/crypto-policies/back-ends/opensshserver.config

/etc/crypto-policies/back-ends/openssh.config:Ciphers aes256-ctr,aes192-ctr,aes128-ctr
/etc/crypto-policies/back-ends/opensshserver.config:CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr'
/etc/crypto-policies/back-ends/opensshserver.config:CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr'

If the cipher entries in the "openssh.config" and "opensshserver.config" files have any ciphers other than "aes256-ctr,aes192-ctr,aes128-ctr", the order differs from the example above, if they are missing, or commented out, this is a finding.)
  desc 'fix', %q(Configure the RHEL 8 SSH daemon to use only ciphers employing FIPS 140-2-approved algorithms with the following command:

$ sudo fips-mode-setup --enable

Next, update the "/etc/crypto-policies/back-ends/openssh.config" and "/etc/crypto-policies/back-ends/opensshserver.config" files to include these ciphers employing FIPS 140-2-approved algorithms:

/etc/crypto-policies/back-ends/openssh.config:Ciphers aes256-ctr,aes192-ctr,aes128-ctr
/etc/crypto-policies/back-ends/opensshserver.config:CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr'
/etc/crypto-policies/back-ends/opensshserver.config:CRYPTO_POLICY='-oCiphers=aes256-ctr,aes192-ctr,aes128-ctr'

A reboot is required for the changes to take effect.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32921r646867_chk'
  tag severity: 'medium'
  tag gid: 'V-230252'
  tag rid: 'SV-230252r646869_rule'
  tag stig_id: 'RHEL-08-010291'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-32896r646868_fix'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
