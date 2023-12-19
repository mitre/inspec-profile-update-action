control 'SV-100957' do
  title 'HAProxy must generate log records for system startup and shutdown.'
  desc 'Logging must be comprehensive to be useful for both intrusion monitoring and security investigations. Recording the start and stop events of HAProxy will provide useful information to investigators.'
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

If properly configured, the globals section will contain the following:

defaults
  log     global
  option  httplog 

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
option  httplog'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-89999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90307'
  tag rid: 'SV-100957r1_rule'
  tag stig_id: 'VRAU-HA-000035'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-97049r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
