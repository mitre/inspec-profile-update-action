control 'SV-218464' do
  title 'The at directory must be owned by root, bin, sys, daemon, or cron.'
  desc 'If the owner of the "at" directory is not root, bin, or sys, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the "at" directory:

Procedure:
# ls -ld /var/spool/at

If the directory is not owned by root, sys, bin, daemon, or cron, this is a finding.'
  desc 'fix', 'Change the owner of the "at" directory to root, bin, sys, or system.

Procedure:
# chown <root or other system account> <"at" directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19939r562549_chk'
  tag severity: 'medium'
  tag gid: 'V-218464'
  tag rid: 'SV-218464r603259_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19937r562550_fix'
  tag 'documentable'
  tag legacy: ['V-4365', 'SV-64299']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
