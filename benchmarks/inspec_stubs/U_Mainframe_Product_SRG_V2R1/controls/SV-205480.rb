control 'SV-205480' do
  title 'The Mainframe Product must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product restricts audit tool access to system programmers, security administrator, and audit personnel. If access is not restricted, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to restrict audit tool access to system programmers, security administrators, and audit personnel.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5746r299673_chk'
  tag severity: 'medium'
  tag gid: 'V-205480'
  tag rid: 'SV-205480r395829_rule'
  tag stig_id: 'SRG-APP-000121-MFP-000177'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-5746r299674_fix'
  tag 'documentable'
  tag legacy: ['SV-82787', 'V-68297']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
