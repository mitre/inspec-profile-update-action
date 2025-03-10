control 'SV-223538' do
  title 'IBM z/OS must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in /etc/ssh/ directory.

Alternately:

From UNIX System Services ISPF Shell navigate to ribbon select tools.

Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 
sshd_config

If there are no "Ciphers" line or the ciphers list contains any cipher not starting with "3des" or "aes", this is a finding.

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
  tag check_id: 'C-25211r504669_chk'
  tag severity: 'high'
  tag gid: 'V-223538'
  tag rid: 'SV-223538r533198_rule'
  tag stig_id: 'ACF2-OS-000020'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-25199r504670_fix'
  tag 'documentable'
  tag legacy: ['V-97781', 'SV-106885']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
