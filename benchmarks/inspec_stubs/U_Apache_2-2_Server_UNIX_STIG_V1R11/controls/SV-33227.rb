control 'SV-33227' do
  title 'The TRACE  method must be disabled.'
  desc 'Diagnostics help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve server availability. Trace logs are essential to the investigation and prosecution of unauthorized access to web server software and data. However, in standard production operations, use of diagnostics may reveal undiscovered vulnerabilities and ultimately, to compromise of the data. Because of the potential for abuse, the HTTP Trace method should be disabled.'
  desc 'check', 'Enter the following command:

grep "TraceEnable" /usr/local/apache2/conf/httpd.conf.

Review the results for the following directive:

TraceEnable.

For any enabled TraceEnable directives ensure they are part of the server level configuration (i.e. not nested in a <Directory> or <Location> directive). Also ensure that the TraceEnable directive is set to “Off”.

If the TraceEnable directive is not part of the server level configuration and/or is not set to “Off”, this is a finding.

If the directive does not exist in the conf file, this is a finding because the default value is "On".'
  desc 'fix', 'Edit the httpd.conf file and add or set the value of EnableTrace to "Off".'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26325'
  tag rid: 'SV-33227r1_rule'
  tag stig_id: 'WA00550 A22'
  tag gtitle: 'WA00550'
  tag fix_id: 'F-29424r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
