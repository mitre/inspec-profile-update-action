control 'SV-28654' do
  title 'Log file data must contain required data elements.'
  desc 'The use of log files is a critical component of the operation of the Information Systems (IS) used within the DoD, and they can provide invaluable assistance with regard to damage assessment, causation, and the recovery of both affected components and data. They may be used to monitor accidental or intentional misuse of the (IS) and may be used by law enforcement for criminal prosecutions. The use of log files is a requirement within the DoD.'
  desc 'check', 'To verify the log settings:

Default Windows location: :\\Program Files\\Apache Group\\Apache2\\logs\\access.log or :\\Program Files\\Apache Software Foundation\\Apache2.2\\logs\\access.log.

If these directories do not exist, you can search the web server for the httpd.conf config file to determine the location of the logs.

Items to be logged are as shown in this sample line in the httpd.conf file:

LogFormat "%a %A %h %H %l %m %s %t %u %U \\"%{Referer}i\\" " combined

If the web server is not configured to capture the required audit events for all sites and virtual directories, this is a finding.'
  desc 'fix', 'Configure the web server to ensure the log file data includes the required data elements.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-35801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13688'
  tag rid: 'SV-28654r1_rule'
  tag stig_id: 'WG242 W22'
  tag gtitle: 'WG242'
  tag fix_id: 'F-13116r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
