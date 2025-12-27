control 'SV-37754' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36952r1_chk'
  tag severity: 'low'
  tag gid: 'V-22509'
  tag rid: 'SV-37754r1_rule'
  tag stig_id: 'GEN006575'
  tag gtitle: 'GEN006575'
  tag fix_id: 'F-32217r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
