control 'SV-226251' do
  title 'Software certificate installation files must be removed from Windows 2012/2012 R2.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  desc 'check', 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for certificate files or Adobe PreFlight certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of non-certificate installation files from systems is not required. These must be documented with the ISSO.'
  desc 'fix', 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

This does not apply to server-based applications that have a requirement for certificate files, Adobe PreFlight certificate files, or non-certificate installation files with the same extension.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27953r476597_chk'
  tag severity: 'medium'
  tag gid: 'V-226251'
  tag rid: 'SV-226251r794577_rule'
  tag stig_id: 'WN12-GE-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27941r476598_fix'
  tag 'documentable'
  tag legacy: ['SV-53141', 'V-15823']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
