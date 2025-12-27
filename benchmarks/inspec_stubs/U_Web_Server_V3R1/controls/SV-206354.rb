control 'SV-206354' do
  title 'The web server must generate information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', 'Review the web server documentation and configuration to determine if the web server is configured to generate information for external applications monitoring remote access.

If a mechanism is not in place providing information to an external application used to monitor and control access, this is a finding.'
  desc 'fix', 'Configure the web server to provide remote connection information to external monitoring and access control applications.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6615r377654_chk'
  tag severity: 'medium'
  tag gid: 'V-206354'
  tag rid: 'SV-206354r395472_rule'
  tag stig_id: 'SRG-APP-000016-WSR-000005'
  tag gtitle: 'SRG-APP-000016'
  tag fix_id: 'F-6615r377655_fix'
  tag 'documentable'
  tag legacy: ['SV-53035', 'V-40799']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
