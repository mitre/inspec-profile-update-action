control 'SV-79275' do
  title 'The installed version of IE must be a supported version.'
  desc 'Unsupported versions are no longer being evaluated or updated for security related issues.'
  desc 'check', 'Procedure: Open Internet Explorer >> Select Help >> Select About.

Criteria: Internet Explorer 9 is only supported on Windows Vista SP2 and Windows Server 2008 SP2. If the version number of Internet Explorer is any version of Internet Explorer 9, the Operating System in use must be Windows Vista SP2 or Windows Server 2008 SP2.

If Internet Explorer 9 is used on any other Operating System, this is a finding.'
  desc 'fix', 'Upgrade Internet Explorer to a supported software version.'
  impact 0.7
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-65477r1_chk'
  tag severity: 'high'
  tag gid: 'V-64785'
  tag rid: 'SV-79275r1_rule'
  tag stig_id: 'DTBI002 - IE9'
  tag gtitle: 'DTBI002 - Installed version of IE is unsupported'
  tag fix_id: 'F-70717r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
