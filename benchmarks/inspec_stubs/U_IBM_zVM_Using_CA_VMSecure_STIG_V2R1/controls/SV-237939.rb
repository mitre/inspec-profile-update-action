control 'SV-237939' do
  title 'CA VM:Secure product audit records must be offloaded on a weekly basis.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check audit offload procedure.

If it can be determined that the audit records are being offloaded on a weekly basis, this is not a finding.'
  desc 'fix', 'Develop procedures that offload Audit minidisk on a weekly basis.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41149r649655_chk'
  tag severity: 'medium'
  tag gid: 'V-237939'
  tag rid: 'SV-237939r649657_rule'
  tag stig_id: 'IBMZ-VM-000950'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-41108r649656_fix'
  tag 'documentable'
  tag legacy: ['SV-93631', 'V-78925']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
