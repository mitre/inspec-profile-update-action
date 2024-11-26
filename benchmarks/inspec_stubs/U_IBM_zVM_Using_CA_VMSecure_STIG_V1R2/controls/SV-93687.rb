control 'SV-93687' do
  title 'The IBM z/VM System administrator must develop routines and processes for notification in the event of audit failure.'
  desc 'Audit processing failures include, for example, software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Without proper notification vital audit records may be lost.'
  desc 'check', 'Ask the system administrator (SA) for documented routines and procures for notification in the event of audit failure.

If there are no routines or procedures or they are not documented and filed with the ISSO, this is a finding.'
  desc 'fix', 'Develop a procedure for notification in the event of audit failure.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78569r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78981'
  tag rid: 'SV-93687r1_rule'
  tag stig_id: 'IBMZ-VM-002370'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85731r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
