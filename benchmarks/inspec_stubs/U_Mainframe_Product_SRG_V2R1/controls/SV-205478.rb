control 'SV-205478' do
  title 'The Mainframe Product must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product restricts audit information update access to system programmers, security administrators, and audit personnel.

If access is not restricted, this is a finding. 

If an external security manager (ESM) is being used, examine the external security configuration and rules.

If the rules do not restrict update access to system programmers, security managers, and audit personnel, this is a finding.'
  desc 'fix', 'Verify the Mainframe Product restricts update or greater access to system programmers, security administrators, and audit personnel.

This can be accomplished using an ESM.

Configure the Mainframe Product to provide an SAF call for audit information access.

Verify ESM rules restrict update or greater access to system programmers, security administrators, and audit personnel.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5744r299667_chk'
  tag severity: 'medium'
  tag gid: 'V-205478'
  tag rid: 'SV-205478r539592_rule'
  tag stig_id: 'SRG-APP-000119-MFP-000175'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-5744r539591_fix'
  tag 'documentable'
  tag legacy: ['SV-82783', 'V-68293']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
