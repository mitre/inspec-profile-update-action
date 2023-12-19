control 'SV-240045' do
  title 'HAProxy must log what type of events occurred.'
  desc 'Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

When configured for httplog, HAProxy logs uses the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures the type of web server event in addition to other useful information. This will enable forensic analysis of server events in case of a malicious event.'
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

Verify that HAProxy is logging the type of events to the log file. 

If the log file is not recording the type of events, this is a finding.'
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
  tag check_id: 'C-43278r665302_chk'
  tag severity: 'medium'
  tag gid: 'V-240045'
  tag rid: 'SV-240045r879563_rule'
  tag stig_id: 'VRAU-HA-000050'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-43237r665303_fix'
  tag 'documentable'
  tag legacy: ['SV-100959', 'V-90309']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
