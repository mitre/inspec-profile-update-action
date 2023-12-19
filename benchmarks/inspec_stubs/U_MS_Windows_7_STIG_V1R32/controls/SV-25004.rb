control 'SV-25004' do
  title 'Software certificate installation files must be removed from a system.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, then this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).  Some applications create files with extensions of .p12 that are NOT certificate installation files.  Removal from systems of non-certificate installation files are not required.  These should be documented with the ISSO.'
  desc 'fix', 'Remove any certificate installation files found on a system.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15823'
  tag rid: 'SV-25004r2_rule'
  tag gtitle: 'Software Certificate Installation Files'
  tag fix_id: 'F-66985r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
