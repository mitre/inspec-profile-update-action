control 'SV-258037' do
  title 'RHEL 9 must enable Linux audit logging for the USBGuard daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DOD has defined the list of events for which RHEL 9 will provide an audit record generation capability as the following:

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.'
  desc 'check', 'To verify that Linux Audit logging is enabled for the USBGuard daemon with the following command:

$ sudo grep AuditBackend /etc/usbguard/usbguard-daemon.conf 

AuditBackend=LinuxAudit 

If "AuditBackend" is not set to "LinuxAudit", this is a finding.'
  desc 'fix', 'Configure RHEL 9 USBGuard AuditBackend to use the audit system.

Add or edit the following line in /etc/usbguard/usbguard-daemon.conf 

AuditBackend=LinuxAudit'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61778r926096_chk'
  tag severity: 'low'
  tag gid: 'V-258037'
  tag rid: 'SV-258037r926098_rule'
  tag stig_id: 'RHEL-09-291025'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-61702r926097_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
