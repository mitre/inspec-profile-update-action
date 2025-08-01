control 'SV-48546' do
  title 'Software certificate installation files must be removed from a system.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).  Some applications create files with extensions of .p12 that are NOT certificate installation files.  Removal of non-certificate installation files from systems is not required.  These must be documented with the ISSO.'
  desc 'fix', 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

Note:  This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44936r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15823'
  tag rid: 'SV-48546r2_rule'
  tag stig_id: 'WN08-GE-000020'
  tag gtitle: 'Software Certificate Installation Files'
  tag fix_id: 'F-41393r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
