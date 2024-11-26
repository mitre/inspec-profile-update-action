control 'SV-45914' do
  title 'The system package management tool must be used to verify system software periodically.'
  desc 'Verification using the system package management tool can be used to determine that system software has not been tampered with.

This requirement is not applicable to systems not using package management tools.'
  desc 'check', %q(Check the root crontab (crontab -l) and the global crontabs in "/etc/crontab", "/etc/cron.d/*" for the presence of an rpm verification command such as:
rpm -qVa | awk '$2!="c" {print $0}'
If no such cron job is found, this is a finding.
If the result of the cron job indicates packages which do not pass verification exist, this is a finding unless the changes were made due to another STIG entry.)
  desc 'fix', %q(Add a cron job to run an rpm verification command such as:
rpm -qVa | awk '$2!="c" {print $0}'

For packages which failed verification:
If the package is not necessary for operations, remove it from the system.

If the package is necessary for operations, re-install the package.)
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43223r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22506'
  tag rid: 'SV-45914r2_rule'
  tag stig_id: 'GEN006565'
  tag gtitle: 'GEN006565'
  tag fix_id: 'F-39293r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366', 'CCI-000698']
  tag nist: ['CM-6 b', 'SA-10 (1)']
end
