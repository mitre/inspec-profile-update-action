control 'SV-227732' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the auditing configuration of the system.
# grep flags /etc/security/audit_control
If the am flag is not present, and either of the -am or +am flags is not present, this is a finding.'
  desc 'fix', 'Edit /etc/security/audit_control and add am to the flags list.
Load the new audit configuration.
# auditconfig -conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29894r488780_chk'
  tag severity: 'medium'
  tag gid: 'V-227732'
  tag rid: 'SV-227732r603266_rule'
  tag stig_id: 'GEN002760'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-29882r488781_fix'
  tag 'documentable'
  tag legacy: ['SV-27298', 'V-816']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
