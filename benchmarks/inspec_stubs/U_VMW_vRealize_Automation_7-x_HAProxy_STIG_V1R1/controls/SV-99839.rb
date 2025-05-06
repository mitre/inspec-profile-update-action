control 'SV-99839' do
  title 'HAProxy must be configured to use syslog.'
  desc 'There are many aspects of appropriate web server logging for security. Storage capacity must be adequate. ISSO and SA must receive warnings and alerts when storage capacity is filled to 75%.

Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.

This requirement can be met by configuring the web server to utilize a dedicated log tool that meets this requirement.'
  desc 'check', 'Navigate to and open /etc/haproxy/haproxy.cfg

Navigate to the "globals" section.

Verify that the "globals" section contains the "log" keyword, and that the "log" option contains the local0 syslog facility as its parameter.

If properly configured, the "globals" section will contain the following:

global
 log 127.0.0.1   local0

If the local0 syslog facility is not configured, this is a finding.

Navigate to the "defaults" section.

Verify that the "defaults" section contains the "log" keyword with the global value.

Verify that an option keyword has been configured with the "httplog" value.

If properly configured, the "defaults" section will contain the following:

defaults
  log     global
  option  httplog 

Navigate to and open the following files:

/etc/haproxy/conf.d/30-vro-config.cfg 
/etc/haproxy/conf.d/20-vcac.cfg

Navigate to the each frontend section.

Verify that the "log" keyword has not been set for each frontend.  

If the "log" keyword is present in a frontend, this is a finding.

Navigate to and open /etc/rsyslog.d/vcac.conf.

Review the configured syslog facilities and determine the location of the log file for the local0 syslog facility.  

If the local0 syslog facility does not refer to a valid log file, this is a finding.

Navigate to and open the local0 syslog log file.

Verify that HAProxy is logging start and stop events to the log file.  

If the log file is not recording HAProxy start and stop events, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/rsyslog.d/vcac.conf.

Configure the local0 syslog facility to write to an appropriate log file.

Navigate to and open /etc/haproxy/haproxy.cfg.

Configure the "globals" section with the following: 

log 127.0.0.1 local0

Configure the "defaults" section with both of the following:

log     global
option  httplog

Navigate to and open the following files:

/etc/haproxy/conf.d/30-vro-config.cfg 
/etc/haproxy/conf.d/20-vcac.cfg

Navigate to each frontend section.

Remove any log options from each frontend.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88881r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89189'
  tag rid: 'SV-99839r1_rule'
  tag stig_id: 'VRAU-HA-000360'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag fix_id: 'F-95931r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
