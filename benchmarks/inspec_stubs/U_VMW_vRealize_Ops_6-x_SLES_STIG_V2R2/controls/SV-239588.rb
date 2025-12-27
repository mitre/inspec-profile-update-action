control 'SV-239588' do
  title 'The SLES for vRealize must notify System Administrators and Information System Security Officers when accounts are disabled.'
  desc 'When SLES for vRealize accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual SLES for vRealize users or for identifying the SLES for vRealize processes themselves.

In order to detect and respond to events that affect user accessibility and system processing, operating systems must audit account disabling actions and, as required, notify System Administrators and Information System Security Officers (ISSO) so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many SLES for vRealize systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
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
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42821r662213_chk'
  tag severity: 'low'
  tag gid: 'V-239588'
  tag rid: 'SV-239588r662215_rule'
  tag stig_id: 'VROM-SL-000920'
  tag gtitle: 'SRG-OS-000276-GPOS-00106'
  tag fix_id: 'F-42780r662214_fix'
  tag 'documentable'
  tag legacy: ['SV-99297', 'V-88647']
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
