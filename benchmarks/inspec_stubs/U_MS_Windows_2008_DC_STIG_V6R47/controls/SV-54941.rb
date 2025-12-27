control 'SV-54941' do
  title 'Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data-in-transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data.'
  desc 'Commercial-grade encryption does not provide adequate protection when the classification level of directory data in transit is higher than the level of the network.'
  desc 'check', 'With the assistance of the SA, NSO, or network reviewer as required, review the site network diagram(s) or documentation to determine the level of classification for the network(s) over which replication data is transmitted.

Determine the classification level of the Windows domain controller.

If the classification level of the Windows domain controller is higher than the level of the networks, review the site network diagram(s) and directory implementation documentation to determine if NSA-approved encryption is used to protect the replication network traffic.

If the classification level of the Windows domain controller is higher than the level of the network traversed and NSA-approved encryption is not used, this is a finding.'
  desc 'fix', 'Configure NSA-approved (Type 1) cryptography to protect the directory data in transit for directory service implementations at a classified confidentiality level that transfers replication data through a network cleared to a lower level than the data.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-48701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14783'
  tag rid: 'SV-54941r2_rule'
  tag stig_id: 'DS00.3281_2008'
  tag gtitle: 'Replication Encryption – Classification Factor'
  tag fix_id: 'F-47822r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
