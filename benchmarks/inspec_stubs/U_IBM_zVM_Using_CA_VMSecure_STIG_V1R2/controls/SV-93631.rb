control 'SV-93631' do
  title 'CA VM:Secure product audit records must be offloaded on a weekly basis.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check audit offload procedure.

If it can be determined that the audit records are being offloaded on a weekly basis, this is not a finding.'
  desc 'fix', 'Develop procedures that offload Audit minidisk on a weekly basis.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78925'
  tag rid: 'SV-93631r1_rule'
  tag stig_id: 'IBMZ-VM-000950'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-85675r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
