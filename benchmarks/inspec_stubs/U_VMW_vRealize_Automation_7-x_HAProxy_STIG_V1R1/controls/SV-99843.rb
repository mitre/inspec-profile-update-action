control 'SV-99843' do
  title 'HAProxy must be configurable to integrate with an organizations security infrastructure.'
  desc 'A web server will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application. While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur. Manual review of the web server logs may not occur in a timely manner, and each event logged is open to interpretation by a reviewer. By integrating the web server into an overall or organization-wide log review, a larger picture of events can be viewed, and analysis can be done in a timely and reliable manner.'
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

Navigate to and open /etc/haproxy/haproxy.cfg.  Configure the globals section with the following:

log 127.0.0.1 local0

Configure the defaults section with both of the following:

log     global
option  httplog'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88885r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89193'
  tag rid: 'SV-99843r1_rule'
  tag stig_id: 'VRAU-HA-000370'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-95935r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
