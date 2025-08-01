control 'SV-38477' do
  title 'System audit logs must be owned by root.'
  desc 'Failure to give ownership of system audit log files to root provides the designated owner and unauthorized users with the potential to access sensitive information.'
  desc 'check', 'Inspect the auditing configuration file, /etc/rc.config.d/auditing, to determine the filename and path of the audit logs. The entries should appear similar to the following:
PRI_AUDFILE=/var/.audit/file1
SEC_AUDFILE=/var/.audit/file2

# egrep “PRI_AUDFILE|SEC_AUDFILE” /etc/rc.config.d/auditing

For each audit log directory/file, check the ownership.
# ls -lLd <audit directory>
# ls -lLa <audit file>

If any audit log directory/file is not owned by root, this is a finding.'
  desc 'fix', 'As root, change the ownership.
# chown root  <audit directory>
# chown root  <audit file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36424r2_chk'
  tag severity: 'medium'
  tag gid: 'V-812'
  tag rid: 'SV-38477r2_rule'
  tag stig_id: 'GEN002680'
  tag gtitle: 'GEN002680'
  tag fix_id: 'F-31763r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
