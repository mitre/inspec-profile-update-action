control 'SV-218670' do
  title 'The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents.'
  desc 'File integrity tools often use cryptographic hashes for verifying that file contents have not been altered.  These hashes must be FIPS 140-2 approved.'
  desc 'check', 'If using an Advanced Intrusion Detection Environment (AIDE), verify the configuration contains the "sha256" or "sha512" options for all monitored files and directories.

Procedure:
Check for the default location /etc/aide/aide.conf
or:
# find / -name aide.conf

# egrep "[+]?(sha256|sha512)" <aide.conf file>
If the option is not present. This is a finding.
If one of these options is not present. This is a finding.

If using a different file integrity tool, check the configuration per tool documentation.'
  desc 'fix', %q(If using AIDE, edit the configuration and add the "sha512" option for all monitored files and directories.

If using a different file integrity tool, configure FIPS 140-2 approved cryptographic hashes per the tool's documentation.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20145r562921_chk'
  tag severity: 'low'
  tag gid: 'V-218670'
  tag rid: 'SV-218670r603259_rule'
  tag stig_id: 'GEN006575'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-20143r562922_fix'
  tag 'documentable'
  tag legacy: ['V-22509', 'SV-63653']
  tag cci: ['CCI-001297', 'CCI-001496']
  tag nist: ['SI-7', 'AU-9 (3)']
end
