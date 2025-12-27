control 'SV-226610' do
  title 'Audit logs must be rotated daily.'
  desc 'Rotate audit logs daily to preserve audit file system space and to conform to the DoD/DISA requirement.  If it is not rotated daily and moved to another location, then there is more of a chance for the compromise of audit data by malicious users.'
  desc 'check', "Check for any crontab entries that rotate audit logs.
Procedure:
# crontab -l
If such a cron job is found, this is not a finding.

Otherwise, query the SA. If there is a process automatically rotating audit logs, this is not a finding. If the SA manually rotates audit logs, this is still a finding, because if the SA is not there, it will not be accomplished. If the audit output is not archived daily, to tape or disk, this is a finding. This can be ascertained by looking at the audit log directory and, if more than one file is there, or if the file does not have today's date, this is a finding."
  desc 'fix', 'Configure a cron job or other automated process to rotate the audit logs on a daily basis.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28771r483242_chk'
  tag severity: 'medium'
  tag gid: 'V-226610'
  tag rid: 'SV-226610r603265_rule'
  tag stig_id: 'GEN002860'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28759r483243_fix'
  tag 'documentable'
  tag legacy: ['SV-4357', 'V-4357']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
