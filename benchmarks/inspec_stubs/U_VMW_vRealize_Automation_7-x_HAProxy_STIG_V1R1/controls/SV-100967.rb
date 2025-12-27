control 'SV-100967' do
  title 'HAProxy must log the outcome of events.'
  desc 'Ascertaining the outcome of an event is important during forensic analysis. The correct determination of the event and its outcome is important in relation to other events that happened at that same time. 

Without sufficient information establishing the outcome of an event, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

When configured for httplog, HAProxy logs uses the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures the success or failure of the web server event in addition to other useful information. This will enable forensic analysis of server events in case of a malicious event.'
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

Verify that HAProxy is logging the outcome of web server events to the log file. 

If the log file is not recording the outcome of events, this is a finding.'
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
  tag check_id: 'C-90009r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90317'
  tag rid: 'SV-100967r1_rule'
  tag stig_id: 'VRAU-HA-000075'
  tag gtitle: 'SRG-APP-000099-WSR-000061'
  tag fix_id: 'F-97059r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
