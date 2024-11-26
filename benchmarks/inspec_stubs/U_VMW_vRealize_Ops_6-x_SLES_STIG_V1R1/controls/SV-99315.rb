control 'SV-99315' do
  title 'The SLES for vRealize must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check the syslog configuration file for remote syslog servers:

# cat /etc/syslog-ng/syslog-ng.conf | grep logserver

If no line is returned, or the "logserver" is commented out, this is a finding.'
  desc 'fix', 'Edit the syslog configuration file and add an appropriate remote syslog server:

In the "/etc/syslog-ng/syslog-ng.conf" file, the remote logging entries must be uncommented and the IP address must be modified to point to the remote syslog server:

# 
# Enable this and adopt IP to send log messages to a log server. 
# 
#destination logserver { udp("10.10.10.10" port(514)); };
#log { source(src); destination(logserver); };'
  impact 0.3
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88357r1_chk'
  tag severity: 'low'
  tag gid: 'V-88665'
  tag rid: 'SV-99315r1_rule'
  tag stig_id: 'VROM-SL-001035'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-95407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
