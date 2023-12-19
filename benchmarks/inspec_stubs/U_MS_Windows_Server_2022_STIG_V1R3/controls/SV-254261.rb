control 'SV-254261' do
  title 'Windows Server 2022 must have software certificate installation files removed.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files or Adobe PreFlight certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of noncertificate installation files from systems is not required. These must be documented with the Information System Security Officer (ISSO).'
  desc 'fix', 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

Note: This does not apply to server-based applications that have a requirement for .p12 certificate files or Adobe PreFlight certificate files.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57746r848597_chk'
  tag severity: 'medium'
  tag gid: 'V-254261'
  tag rid: 'SV-254261r848599_rule'
  tag stig_id: 'WN22-00-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57697r848598_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
