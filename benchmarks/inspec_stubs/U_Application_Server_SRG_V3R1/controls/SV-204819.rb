control 'SV-204819' do
  title 'The application server must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue.  This queue may be part of the application server so error messages from the server can be sent to system administrators, or SMTP functionality can be added to hosted applications by developers.

Any modules used by the application server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', 'Review the application server documentation and deployed configuration to determine if the application server maintains the confidentiality and integrity of information during preparation before transmission.

If the confidentiality and integrity is not maintained, this is a finding.'
  desc 'fix', 'Configure the application server to maintain the confidentiality and integrity of information during preparation for transmission.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4939r283098_chk'
  tag severity: 'medium'
  tag gid: 'V-204819'
  tag rid: 'SV-204819r508029_rule'
  tag stig_id: 'SRG-APP-000441-AS-000258'
  tag gtitle: 'SRG-APP-000441'
  tag fix_id: 'F-4939r283099_fix'
  tag 'documentable'
  tag legacy: ['SV-71813', 'V-57537']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
