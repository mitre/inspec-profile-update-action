control 'SV-237932' do
  title 'The IBM z/VM AUDT and Journal Mini Disks must be restricted to the appropriate system administrators.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Examine the CA VM:Secure rules.

If there are Link rules for audit disk granted to anyone other than system administrators, security administrators, or system auditors, this is a finding.'
  desc 'fix', 'Create a CA VM:Secure rule that grants access to system administrators, security administrators, or system auditors only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41142r649634_chk'
  tag severity: 'medium'
  tag gid: 'V-237932'
  tag rid: 'SV-237932r649636_rule'
  tag stig_id: 'IBMZ-VM-000840'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-41101r649635_fix'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag legacy: ['SV-93617', 'V-78911']
  tag cci: ['CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9']
end
