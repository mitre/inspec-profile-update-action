control 'SV-223807' do
  title 'The IBM RACF SSH daemon must be configured to use a FIPS 140-2 compliant cryptographic algorithm to protect confidential information and remote access sessions.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. Cryptographic modules must adhere to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in /etc/ssh/ directory.

Alternately:
From UNIX System Services ISPF Shell navigate to ribbon select tools.
Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 
sshd_config

If there are no "Ciphers" lines or the ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.

If the MACs line is not configured to "hmac-sha1" or greater this is a finding.

Examine the z/OS-specific sshd server system-wide configuration: 
zos_sshd_config

If any of the following is untrue, this is a finding.

FIPSMODE=YES
CiphersSource=ICSF
MACsSource=ICSF'
  desc 'fix', 'Edit the SSH daemon configuration and remove any ciphers not starting with "3des" or "aes". If necessary, add a "Ciphers" line using FIPS 140-2 compliant algorithms.

Configure for message authentication to MACs "hmac-sha1" or greater.

Edit the z/OS-specific sshd server system-wide configuration file configuration as follows:
FIPSMODE=YES
CiphersSource=ICSF
MACsSource=ICSF'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25480r515109_chk'
  tag severity: 'high'
  tag gid: 'V-223807'
  tag rid: 'SV-223807r877398_rule'
  tag stig_id: 'RACF-SH-000020'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-25468r515110_fix'
  tag 'documentable'
  tag legacy: ['V-98321', 'SV-107425']
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'AC-17 (2)']
end
