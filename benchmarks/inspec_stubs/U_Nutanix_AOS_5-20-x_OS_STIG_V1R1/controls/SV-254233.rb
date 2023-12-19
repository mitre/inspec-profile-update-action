control 'SV-254233' do
  title 'Nutanix AOS must reveal error messages only to authorized users.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Nutanix AOS audit logs must be owned by root to prevent unauthorized read access.

Determine where the audit log file is located:
$sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /home/log/audit/audit.log

Using the location of the audit log file, determine if the audit log is owned by "root" using the following command:
ls -al /home/log/audit/audit.log
-rw-------. 1 root root 3427758 Apr  8 18:43 /home/log/audit/audit.log

If the audit log is not owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit rules ownership by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57718r846785_chk'
  tag severity: 'medium'
  tag gid: 'V-254233'
  tag rid: 'SV-254233r846787_rule'
  tag stig_id: 'NUTX-OS-001570'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-57669r846786_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
