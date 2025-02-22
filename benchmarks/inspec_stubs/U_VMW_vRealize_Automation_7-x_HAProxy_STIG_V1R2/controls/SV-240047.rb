control 'SV-240047' do
  title 'HAProxy must log where events occurred.'
  desc 'Ascertaining where an event occurred is important during forensic analysis. The correct determination of the event and where on the web server it occurred is important in relation to other events that happened at that same time. 

Without sufficient information establishing where an event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

When configured for httplog, HAProxy logs uses the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures the local resource that was the target of a web server event in addition to other useful information. This will enable forensic analysis of server events in case of a malicious event.'
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

Verify that HAProxy is logging where on the web server resources were requested to the log file. 

If the log file is not recording where the events occurred, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/rsyslog.d/vcac.conf.

Configure the local0 syslog facility to write to an appropriate log file.

Navigate to and open /etc/haproxy/haproxy.cfg.

Configure the globals section with the following: 

log 127.0.0.1 local0

Configure the defaults section with both of the following:

log     global
option  httplog'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43280r665308_chk'
  tag severity: 'medium'
  tag gid: 'V-240047'
  tag rid: 'SV-240047r879565_rule'
  tag stig_id: 'VRAU-HA-000060'
  tag gtitle: 'SRG-APP-000097-WSR-000058'
  tag fix_id: 'F-43239r665309_fix'
  tag 'documentable'
  tag legacy: ['SV-100963', 'V-90313']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
