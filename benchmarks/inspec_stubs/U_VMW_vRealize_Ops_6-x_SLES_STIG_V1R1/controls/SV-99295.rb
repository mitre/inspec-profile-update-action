control 'SV-99295' do
  title 'The SLES for vRealize must notify System Administrators and Information System Security Officers when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail, which documents the creation of SLES for vRealize user accounts and notifies System Administrators and Information System Security Officers (ISSO) that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

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
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88337r1_chk'
  tag severity: 'low'
  tag gid: 'V-88645'
  tag rid: 'SV-99295r1_rule'
  tag stig_id: 'VROM-SL-000915'
  tag gtitle: 'SRG-OS-000275-GPOS-00105'
  tag fix_id: 'F-95387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
