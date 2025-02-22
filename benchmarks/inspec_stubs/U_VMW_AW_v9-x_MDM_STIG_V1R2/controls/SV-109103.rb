control 'SV-109103' do
  title 'Only authorized versions of AirWatch Console/Workspace One UEM Console must be used.'
  desc 'AirWatch Console/Workspace One UEM Console version 9.7 and earlier releases are no longer supported by VMware and therefore, may contain security vulnerabilities. AirWatch Console/Workspace One UEM Console version 9.7 and earlier releases are not authorized within the DoD.

CCI: CCI-000366'
  desc 'check', 'Interview ISSO and site MDM system administrator.

Verify the site is not using AirWatch Console/Workspace One UEM Console version 9.7 and earlier releases.

If the site is using AirWatch Console/Workspace One UEM Console version 9.7 and earlier releases, this is a finding.'
  desc 'fix', 'Remove all AirWatch Console/Workspace One UEM Console version 9.7 and earlier releases.'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-98849r1_chk'
  tag severity: 'high'
  tag gid: 'V-99999'
  tag rid: 'SV-109103r1_rule'
  tag stig_id: 'VMAW-09-999999'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105683r1_fix'
  tag 'documentable'
end
