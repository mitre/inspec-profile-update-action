control 'SV-48016' do
  title 'Systems must be maintained at a supported version of an operating system.'
  desc 'Systems at unsupported versions or releases of an operating system will not receive security updates for new vulnerabilities which leaves them subject to exploitation.  Systems must be maintained at a version of the operating system supported by the vendor with new security updates.'
  desc 'check', 'Support for the initial release of Windows 8 ended 12 January 2016.  After this date, systems must have Windows 8.1 installed.

Run "winver.exe".

If the "About Windows" dialog box does not display:
"Microsoft Windows
Version 6.3 (Build 9600)"
or greater this is a finding.'
  desc 'fix', 'Update the system to a version of the operating system supported by the vendor.

Support for the initial release of Windows 8 ended 12 January 2016.  After this date, systems must have Windows 8.1 installed.'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-64123r1_chk'
  tag severity: 'high'
  tag gid: 'V-1073'
  tag rid: 'SV-48016r2_rule'
  tag stig_id: 'WN08-GE-000001'
  tag gtitle: 'Unsupported Service Packs'
  tag fix_id: 'F-69303r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
