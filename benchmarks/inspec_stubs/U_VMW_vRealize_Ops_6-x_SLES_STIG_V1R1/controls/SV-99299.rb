control 'SV-99299' do
  title 'The SLES for vRealize must notify System Administrators and Information System Security Officers when accounts are removed.'
  desc 'When SLES for vRealize accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual SLES for vRealize users or for identifying the SLES for vRealize processes themselves.

In order to detect and respond to events that affect user accessibility and system processing, SLES for vRealize must audit account removal actions and, as required, notify System Administrators and Information System Security Officers (ISSO) so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
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
  tag check_id: 'C-88341r1_chk'
  tag severity: 'low'
  tag gid: 'V-88649'
  tag rid: 'SV-99299r1_rule'
  tag stig_id: 'VROM-SL-000925'
  tag gtitle: 'SRG-OS-000277-GPOS-00107'
  tag fix_id: 'F-95391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
