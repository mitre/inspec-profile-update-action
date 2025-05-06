control 'SV-44765' do
  title 'A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.'
  desc 'Changes in system libraries, binaries and other critical system files can indicate compromise or significant system events such as patching needing to be checked by automated processes and the results reviewed by the SA.

NOTE: For MAC I systems, increase the frequency to daily.'
  desc 'check', 'Determine if there is an automated job, scheduled to run weekly or more frequently, to run the file integrity tool to check for unauthorized additions to system libraries. The check can be done using Advanced Intrusion Detection Environment (AIDE) which is part of the SUSE Linux Enterprise Server (SLES) distribution. Other file integrity software may be used but must be checked manually. 

Procedure:
Check the root crontab (crontab -l) and the global crontabs in /etc/crontab, /etc/cron.d/* for the presence of an "aide" job to run at least weekly, which should have asterisks (*) in columns 3, 4, and 5.

Check the weekly cron directory (/etc/cron.weekly) for any script running "aide --check" or "aide -C" or simply "aide". If one does not exist, this is a finding.'
  desc 'fix', 'Establish an automated job, scheduled to run weekly or more frequently, to run the file integrity tool to check for unauthorized system libraries or binaries, or unauthorized modification to authorized system libraries or binaries.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42270r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11945'
  tag rid: 'SV-44765r1_rule'
  tag stig_id: 'GEN000220'
  tag gtitle: 'GEN000220'
  tag fix_id: 'F-38215r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001069']
  tag nist: ['RA-5 (7)']
end
