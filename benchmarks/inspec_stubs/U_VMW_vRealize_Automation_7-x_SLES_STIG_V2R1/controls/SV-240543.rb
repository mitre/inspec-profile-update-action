control 'SV-240543' do
  title 'The SLES for vRealize must, at a minimum, off-load audit information on interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check the "syslog" configuration file for remote syslog servers:

# cat /etc/syslog-ng/syslog-ng.conf | grep logserver

If no line is returned, or "logserver" is commented out, this is a finding.'
  desc 'fix', 'Edit the syslog configuration file and add an appropriate remote syslog server:

In the /etc/syslog-ng/syslog-ng.conf file, the remote logging entries must be uncommented and the IP address must be modified to point to the remote syslog server:

# 
# Enable this and adopt IP to send log messages to a log server. 
# 
destination logserver { udp("10.10.10.10" port(514)); };
log { source(src); destination(logserver); };'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43776r671368_chk'
  tag severity: 'medium'
  tag gid: 'V-240543'
  tag rid: 'SV-240543r671370_rule'
  tag stig_id: 'VRAU-SL-001495'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-43735r671369_fix'
  tag 'documentable'
  tag legacy: ['SV-100513', 'V-89863']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
