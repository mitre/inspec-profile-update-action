control 'SV-253263' do
  title 'Windows 11 systems must be maintained at a supported servicing level.'
  desc 'Windows 11 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

New versions with feature updates are planned to be released on a semi-annual basis with an estimated support timeframe of 18 to 30 months depending on the release. Support for previously released versions has been extended for Enterprise editions.

A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.'
  desc 'check', 'Run "winver.exe".

If the "About Windows" dialog box does not display "Microsoft Windows 11 Version 21H2 (OS Build 22000.348)" or greater, this is a finding.'
  desc 'fix', 'Update systems on the Semi-Annual Channel to "Microsoft Windows 11 Version 21H2 (OS Build 22000.348)" or greater.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56716r828871_chk'
  tag severity: 'high'
  tag gid: 'V-253263'
  tag rid: 'SV-253263r828873_rule'
  tag stig_id: 'WN11-00-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56666r828872_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
