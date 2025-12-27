control 'SV-248815' do
  title 'OL 8 must take appropriate action when the internal event queue is full.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Offloading is a common process in information systems with limited audit storage capacity. 
 
OL 8 installation media provides "rsyslogd". This is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols) provides a method to securely encrypt and offload auditing.

'
  desc 'check', 'Verify the audit system is configured to take an appropriate action when the internal event queue is full: 
 
$ sudo grep -i overflow_action /etc/audit/auditd.conf 
 
overflow_action = syslog 
 
If the value of the "overflow_action" option is not set to "syslog", "single", or "halt", or the line is commented out, ask the System Administrator to indicate how the audit logs are offloaded to a different system or media.  
 
If there is no evidence that the transfer of the audit logs being offloaded to another system or media takes appropriate action if the internal event queue becomes full, this is a finding.'
  desc 'fix', 'Edit the "/etc/audit/auditd.conf" file and add or update the "overflow_action" option: 
 
overflow_action = syslog 
 
The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52249r780009_chk'
  tag severity: 'medium'
  tag gid: 'V-248815'
  tag rid: 'SV-248815r853840_rule'
  tag stig_id: 'OL08-00-030700'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-52203r780010_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
