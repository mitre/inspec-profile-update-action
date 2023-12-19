control 'SV-240043' do
  title 'HAProxy must be configured to use syslog.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.'
  desc 'check', 'Navigate to and open /etc/haproxy/haproxy.cfg

Navigate to the globals section.

Verify that the globals section contains the log keyword, and that the log option contains the local0 syslog facility as its parameter.

If properly configured, the globals section will contain the following:

global
  log 127.0.0.1   local0

If the local0 syslog facility is not configured, this is a finding.

Navigate to the defaults section.

Verify that the defaults section contains the log keyword with the global value.

Verify that an option keyword has been configured with the httplog value.

If properly configured, the "globals" section will contain the following:

defaults
  log     global
  option  httplog 

Navigate to and open the following files:

/etc/haproxy/conf.d/30-vro-config.cfg 
/etc/haproxy/conf.d/20-vcac.cfg

Navigate to the each frontend section.

Verify that the log keyword has not been set for each frontend. 

If the log keyword is resent in a frontend, this is a finding.

Navigate to and open /etc/rsyslog.d/vcac.conf.

Review the configured syslog facilities and determine the location of the log file for the local0 syslog facility. 

If the local0 syslog facility does not refer to a valid log file, this is a finding.

Navigate to and open the local0 syslog log file.

Verify that HAProxy is logging start and stop events to the log file. 

If the log file is not recording HAProxy start and stop events, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/rsyslog.d/vcac.conf.

Configure the local0 syslog facility to write to an appropriate log file.

Navigate to and open /etc/haproxy/haproxy.cfg.

Configure the globals section with the following: 

log 127.0.0.1 local0

Configure the defaults section with both of the following:

log     global
option  httplog

Navigate to and open the following files:

/etc/haproxy/conf.d/30-vro-config.cfg 
/etc/haproxy/conf.d/20-vcac.cfg

Navigate to each frontend section.

Remove any log options from each frontend.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43276r665296_chk'
  tag severity: 'medium'
  tag gid: 'V-240043'
  tag rid: 'SV-240043r879521_rule'
  tag stig_id: 'VRAU-HA-000025'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-43235r665297_fix'
  tag 'documentable'
  tag legacy: ['SV-100955', 'V-90305']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
