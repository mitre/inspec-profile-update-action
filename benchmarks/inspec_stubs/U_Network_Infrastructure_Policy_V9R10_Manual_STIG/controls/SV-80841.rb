control 'SV-80841' do
  title 'Syslog messages must be retained for a minimum of 30 days online and then stored offline for one year.'
  desc 'Logging is a critical part of router security.  Maintaining an audit trail of system activity logs (syslog) can help identify configuration errors, understand past intrusions, troubleshoot service disruptions, and react to probes and scans of the network.'
  desc 'check', 'Examine the syslog server to verify that it is configured to store messages for at least 30 days.  Have the administrator show you the syslog files stored offline for one year.

If the syslog messages are not kept online for thirty days and offline for one year, this is a finding.'
  desc 'fix', 'Configure the syslog server to store messages for at least 30 days on-line. The administrator must establish a strategy for storing the logs off-line for minimum of 1 year.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-66997r1_chk'
  tag severity: 'low'
  tag gid: 'V-66351'
  tag rid: 'SV-80841r1_rule'
  tag stig_id: 'NET1026'
  tag gtitle: 'NET1026'
  tag fix_id: 'F-72427r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000167']
  tag nist: ['AU-11']
end
