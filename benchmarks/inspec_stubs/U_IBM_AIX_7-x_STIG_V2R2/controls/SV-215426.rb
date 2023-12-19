control 'SV-215426' do
  title 'AIX package management tool must be used daily to verify system software.'
  desc 'Verification using the system package management tool can be used to determine that system software has not been tampered with. This requirement is not applicable to systems not using package management tools.'
  desc 'check', 'Check the root crontab for a daily job invoking the system package management tool to verify the integrity of installed packages.

From the command prompt, run the following command: 

# crontab -l | grep lppchk 
55 22 * * * /lppchk.sh # Daily LPP check script

If no such job exists, this is a finding.'
  desc 'fix', 'Add a job to the root crontab invoking the following system package management tool to verify the integrity of installed packages and email the result to root user.

Run the following command to add the cron job: 
# crontab -e

Within crontab command, add the following daily job to the cron table, then save the change:
0 23 * * * /usr/bin/lppchk -c > /tmp/111 2>&1; sendmail root < /tmp/111'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16624r294729_chk'
  tag severity: 'medium'
  tag gid: 'V-215426'
  tag rid: 'SV-215426r508663_rule'
  tag stig_id: 'AIX7-00-003131'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16622r294730_fix'
  tag 'documentable'
  tag legacy: ['SV-101809', 'V-91711']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
