control 'SV-25257' do
  title 'Systems must be at supported service pack (SP) or release levels.'
  desc 'Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities and leaves them subject to exploitation.  Systems must be maintained at a service pack level supported by the vendor with new security updates.'
  desc 'check', 'Run "winver.exe". 

If the "About Windows" dialog box does not display the following version or greater, this is a finding.
"Microsoft Windows
Version 6.1 (Build 7601: Service Pack 1)"
      
No Release Candidates or Beta versions will be used in a production environment. 

The initial release of Windows 7 is unsupported as of 9 April 2013. Systems must be updated to Service Pack 1.'
  desc 'fix', 'Update the system to a version of the operating system supported by the vendor.

Support for Windows 2008/2008 R2 ended 14 January 2020. After this date, systems must have Windows 2012 or greater installed.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-45632r1_chk'
  tag severity: 'high'
  tag gid: 'V-1073'
  tag rid: 'SV-25257r3_rule'
  tag gtitle: 'Unsupported Service Packs'
  tag fix_id: 'F-30098r4_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
