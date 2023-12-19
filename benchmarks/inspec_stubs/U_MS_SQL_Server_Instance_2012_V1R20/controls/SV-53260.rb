control 'SV-53260' do
  title 'SQL Server must identify potential security-relevant error conditions.'
  desc 'The structure and content of SQL Server error messages need to be carefully considered by the organization and development team. The extent to which the application is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Database logs can be monitored for specific security-related errors. Any error that can have a negative effect on database security should be quickly identified and forwarded to the appropriate personnel. If security-relevant error conditions are not identified by SQL Server they may be overlooked by the personnel responsible for addressing them.'
  desc 'check', 'Security-related errors must be identified and monitored. In most cases, these items would appear in the SQL Server log file.  

If security-related error conditions are not being monitored to meet this requirement, this is a finding.'
  desc 'fix', 'Monitor SQL Server log files to determine when a security-related error occurs.

Add/Update list of appropriate personnel that are to be alerted when a security related error condition occurs to system documentation. Consider an automated job for both the monitor and the alerting.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47561r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40906'
  tag rid: 'SV-53260r2_rule'
  tag stig_id: 'SQL2-00-022700'
  tag gtitle: 'SRG-APP-000265-DB-000161'
  tag fix_id: 'F-46188r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
