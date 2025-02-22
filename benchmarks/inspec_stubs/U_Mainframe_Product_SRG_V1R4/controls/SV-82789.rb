control 'SV-82789' do
  title 'The Mainframe Product must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product restricts audit tool modification to system programmers, security administrator, and audit personnel. If access is not restricted, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to restrict audit tool modification to system programmers, security administrators, and audit personnel.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68299'
  tag rid: 'SV-82789r1_rule'
  tag stig_id: 'SRG-APP-000122-MFP-000178'
  tag gtitle: 'SRG-APP-000122-MFP-000178'
  tag fix_id: 'F-74413r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
