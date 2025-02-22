control 'SV-87923' do
  title 'Software certificate installation files must be removed from Windows Server 2016.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files or Adobe PreFlight certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of non-certificate installation files from systems is not required. These must be documented with the ISSO.'
  desc 'fix', 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

Note: This does not apply to server-based applications that have a requirement for .p12 certificate files or Adobe PreFlight certificate files.'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-94157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73271'
  tag rid: 'SV-87923r2_rule'
  tag stig_id: 'WN16-00-000270'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-101003r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
