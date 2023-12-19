control 'SV-240503' do
  title 'The SLES for vRealize must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check the syslog configuration file for remote syslog servers:

# cat /etc/syslog-ng/syslog-ng.conf | grep logserver

If no line is returned, or "logserver" is commented out, this is a finding.'
  desc 'fix', 'Edit the syslog configuration file and add an appropriate remote syslog server:

In the /etc/syslog-ng/syslog-ng.conf file, the remote logging entries must be uncommented and the IP address must be modified to point to the remote syslog server:

# 
# Enable this and adopt IP to send log messages to a log server. 
# 
destination logserver { udp("x.x.x.x" port(514)); };
log { source(src); destination(logserver); };

Note: Replace x.x.x.x with the appropriate IP address.'
  impact 0.3
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43736r671248_chk'
  tag severity: 'low'
  tag gid: 'V-240503'
  tag rid: 'SV-240503r671250_rule'
  tag stig_id: 'VRAU-SL-001060'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-43695r671249_fix'
  tag 'documentable'
  tag legacy: ['SV-100433', 'V-89783']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
