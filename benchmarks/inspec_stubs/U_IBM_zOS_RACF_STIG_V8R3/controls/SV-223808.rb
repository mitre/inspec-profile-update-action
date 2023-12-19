control 'SV-223808' do
  title 'The IBM z/OS must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in /etc/ssh/ directory.

Alternately:
From UNIX System Services ISPF Shell navigate to ribbon select tools.
Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 
sshd_config

If there are no Ciphers lines or the ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.

If the MACs line is not configured to "hmac-sha1" or greater, this is a finding.

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
  tag check_id: 'C-25481r515112_chk'
  tag severity: 'high'
  tag gid: 'V-223808'
  tag rid: 'SV-223808r604139_rule'
  tag stig_id: 'RACF-SH-000030'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-25469r515113_fix'
  tag 'documentable'
  tag legacy: ['SV-107427', 'V-98323']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
