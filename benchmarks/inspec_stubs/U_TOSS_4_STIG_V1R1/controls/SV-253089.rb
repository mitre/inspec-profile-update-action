control 'SV-253089' do
  title 'TOSS must take appropriate action when the internal event queue is full.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

TOSS installation media provides "rsyslogd." "rsyslogd" is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS, and DTLS protocols), and now there is a method to securely encrypt and off-load auditing.'
  desc 'check', 'Verify the audit system is configured to take an appropriate action when the internal event queue is full:

$ sudo grep -i overflow_action /etc/audit/auditd.conf

overflow_action = syslog

If the value of the "overflow_action" option is not set to "syslog", "single", "halt", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 

If there is no evidence that the transfer of the audit logs being off-loaded to another system or media takes appropriate action if the internal event queue becomes full, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "overflow_action" option to one of "syslog", "single", or "halt":

overflow_action = syslog

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56542r824937_chk'
  tag severity: 'medium'
  tag gid: 'V-253089'
  tag rid: 'SV-253089r824939_rule'
  tag stig_id: 'TOSS-04-040390'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-56492r824938_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
