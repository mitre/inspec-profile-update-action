control 'SV-223589' do
  title 'IBM z/OS SSH daemon must be configured to use a FIPS 140-2 compliant cryptographic algorithm.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in "/etc/ssh/" directory.

Alternately:

From UNIX System Services ISPF Shell navigate to ribbon select tools.

Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 
sshd_config

If there are no ciphers lines or the ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.

If the MACs line is not configured to "hmac-sha1" or greater, this is a finding.

Examine the z/OS-specific sshd server system-wide configuration. 
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
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25262r504740_chk'
  tag severity: 'high'
  tag gid: 'V-223589'
  tag rid: 'SV-223589r533198_rule'
  tag stig_id: 'ACF2-SH-000050'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-25250r504741_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag legacy: ['V-97883', 'SV-106987']
  tag cci: ['CCI-000068', 'CCI-000803']
  tag nist: ['AC-17 (2)', 'IA-7']
end
