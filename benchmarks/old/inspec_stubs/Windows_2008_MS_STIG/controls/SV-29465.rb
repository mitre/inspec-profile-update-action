control 'SV-29465' do
  title 'Software certificate installation files must be removed from Windows 2008.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of non-certificate installation files from systems is not required. These must be documented with the ISSO.'
  desc 'fix', 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

This does not apply to server-based applications that have a requirement for certificate files or non-certificate installation files with the same extension.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-78297r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15823'
  tag rid: 'SV-29465r2_rule'
  tag gtitle: 'Software Certificate Installation Files'
  tag fix_id: 'F-85463r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
