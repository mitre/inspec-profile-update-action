control 'SV-82791' do
  title 'The Mainframe Product must protect audit tools from unauthorized deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product restricts the ability to delete audit tool to system programmers, security administrators, and audit personnel. If access is not restricted, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to restrict audit tool deletion to system programmers, security administrators, and audit personnel.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68301'
  tag rid: 'SV-82791r1_rule'
  tag stig_id: 'SRG-APP-000123-MFP-000179'
  tag gtitle: 'SRG-APP-000123-MFP-000179'
  tag fix_id: 'F-74415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
