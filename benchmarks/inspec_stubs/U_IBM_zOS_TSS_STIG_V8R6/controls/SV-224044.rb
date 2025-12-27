control 'SV-224044' do
  title 'The SSH daemon must be configured to use a FIPS 140-2 compliant cryptographic algorithm.'
  desc 'Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

'
  desc 'check', 'Locate the SSH daemon configuration file which may be found in /etc/ssh/ directory.

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
  desc 'fix', 'Edit the SSH daemon configuration and remove any ciphers not starting with "3des" or "aes". If necessary, add a "Ciphers" line using FIPS 140-2 compliant algorithms.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25717r516758_chk'
  tag severity: 'high'
  tag gid: 'V-224044'
  tag rid: 'SV-224044r561402_rule'
  tag stig_id: 'TSS0-SH-000020'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-25705r516759_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000250-GPOS-00093']
  tag 'documentable'
  tag legacy: ['V-98795', 'SV-107899']
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'IA-7', 'AC-17 (2)']
end
