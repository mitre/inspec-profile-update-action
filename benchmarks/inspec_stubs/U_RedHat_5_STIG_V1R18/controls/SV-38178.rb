control 'SV-38178' do
  title 'A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.'
  desc 'Changes in system libraries, binaries and other critical system files can indicate compromise or significant system events such as patching needing to be checked by automated processes and the results reviewed by the SA.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  desc 'check', 'Check for the presence of an aide on the system:
# rpm –qa | grep aide

If aide is not installed, ask the SA what file integrity tool is being used to check the system.

Check the global crontabs for the presence of an "aide" job to run at least weekly, if aide is installed. Otherwise, check for the presence of a cron job to run the alternate file integrity checking application.

# grep aide /etc/cron*/*

If a tool is being run then the configuration file for the appropriate tool needs to be checked for  selection lines /bin, /sbin, /lib, and /usr.

Procedure:
Check the root crontab (crontab -l) and the global crontabs in /etc/crontab, /etc/cron.d/* for the presence of an "aide" job to run at least weekly, which should have asterisks (*) in columns 3, 4, and 5.

Check the weekly cron directory (/etc/cron.weekly) for any script running "aide --check" or "aide -C" or simply "aide". If there is not, this is a finding.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  desc 'fix', 'Establish an automated job, scheduled to run weekly or more frequently, to run "aide --check" which is the file integrity tool to check for unauthorized system libraries or binaries.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37562r4_chk'
  tag severity: 'medium'
  tag gid: 'V-11945'
  tag rid: 'SV-38178r3_rule'
  tag stig_id: 'GEN000220'
  tag gtitle: 'GEN000220'
  tag fix_id: 'F-32806r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001069']
  tag nist: ['RA-5 (7)']
end
