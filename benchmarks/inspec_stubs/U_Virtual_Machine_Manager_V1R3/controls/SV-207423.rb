control 'SV-207423' do
  title 'The VMM must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

VMMs providing tools to interface with audit data will leverage roles identifying the user accessing the tools and permissions identifying the corresponding rights the user is assigned in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit VMM activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the VMM protects audits tools from unauthorized deletion.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect audit tools from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7680r365679_chk'
  tag severity: 'medium'
  tag gid: 'V-207423'
  tag rid: 'SV-207423r379243_rule'
  tag stig_id: 'SRG-OS-000258-VMM-000920'
  tag gtitle: 'SRG-OS-000258'
  tag fix_id: 'F-7680r365680_fix'
  tag 'documentable'
  tag legacy: ['SV-71307', 'V-57047']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
