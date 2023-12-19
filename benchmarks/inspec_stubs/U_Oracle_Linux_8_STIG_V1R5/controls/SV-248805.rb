control 'SV-248805' do
  title 'OL 8 must enable Linux audit logging for the USBGuard daemon.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify OL 8 enables Linux audit logging of the USBGuard daemon with the following commands. 
 
Note: If the USBGuard daemon is not installed and enabled, this requirement is not applicable. 
 
$ sudo grep -i auditbackend /etc/usbguard/usbguard-daemon.conf 
 
AuditBackend=LinuxAudit 
 
If the "AuditBackend" entry does not equal "LinuxAudit", is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enable Linux audit logging of the USBGuard daemon by adding or modifying the following line in "/etc/usbguard/usbguard-daemon.conf": 
 
AuditBackend=LinuxAudit'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52239r779979_chk'
  tag severity: 'medium'
  tag gid: 'V-248805'
  tag rid: 'SV-248805r779981_rule'
  tag stig_id: 'OL08-00-030603'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-52193r779980_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
