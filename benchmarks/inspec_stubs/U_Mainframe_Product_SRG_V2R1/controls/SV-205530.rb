control 'SV-205530' do
  title 'The Mainframe Product must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step to ensuring the integrity of audit data. Audit data includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs. 

To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage functions, this is not applicable.

Examine the Mainframe Product Installation settings.

If the Mainframe Product does not  use cryptographic mechanisms to protect the integrity of audit tools, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to use cryptographic mechanisms to protect the integrity of audit tools.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5796r299823_chk'
  tag severity: 'medium'
  tag gid: 'V-205530'
  tag rid: 'SV-205530r397882_rule'
  tag stig_id: 'SRG-APP-000290-MFP-000182'
  tag gtitle: 'SRG-APP-000290'
  tag fix_id: 'F-5796r299824_fix'
  tag 'documentable'
  tag legacy: ['SV-82793', 'V-68303']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
