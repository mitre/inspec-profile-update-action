control 'SV-220063' do
  title 'The system package management tool must be used to verify system software periodically.'
  desc 'Verification using the system package management tool can be used to determine that system software has not been tampered with.

This requirement is not applicable to systems not using package management tools.'
  desc 'check', 'Check the root crontab (crontab -l) for the presence of a package check command, such as, pkgchk -n.

If no such cron job is found, this is a finding.'
  desc 'fix', 'Add a cron job to run a package verification command, such as, pkgchk -n.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21772r485495_chk'
  tag severity: 'medium'
  tag gid: 'V-220063'
  tag rid: 'SV-220063r603265_rule'
  tag stig_id: 'GEN006565'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21771r485496_fix'
  tag 'documentable'
  tag legacy: ['V-22506', 'SV-26857']
  tag cci: ['CCI-000698', 'CCI-000366']
  tag nist: ['SA-10 (1)', 'CM-6 b']
end
