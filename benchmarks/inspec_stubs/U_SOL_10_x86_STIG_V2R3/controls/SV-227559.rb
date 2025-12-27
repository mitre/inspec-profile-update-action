control 'SV-227559' do
  title 'A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.'
  desc 'Changes in system libraries and binaries can indicate compromise or significant system events, such as patching needing to be checked by automated processes and the results reviewed by the SA.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  desc 'check', 'Determine if there is a cron job, scheduled to run weekly or more frequently, to run the file integrity tool to check for unauthorized system libraries or binaries, or unauthorized modification to authorized system libraries or binaries. 

Procedure:
# crontab -l

If there is no cron job meeting these requirements, this is a finding.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  desc 'fix', 'Create a cron job, scheduled to run weekly or more frequently, to run the file integrity tool to check for unauthorized system libraries or binaries, or unauthorized modification to authorized system libraries or binaries.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36438r602917_chk'
  tag severity: 'medium'
  tag gid: 'V-227559'
  tag rid: 'SV-227559r854463_rule'
  tag stig_id: 'GEN000220'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-36402r602918_fix'
  tag 'documentable'
  tag legacy: ['V-11945', 'SV-28610']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
