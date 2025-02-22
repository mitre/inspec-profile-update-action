control 'SV-240274' do
  title 'Lighttpd must have the latest approved security-relevant software updates installed.'
  desc 'All vRA components, to include Lighttpd, are under VMware configuration management control. The CM process ensures that all patches, functions, and modules have been thoroughly tested before being introduced into the production version.

By using the most current version of Lighttpd, the Lighttpd server will always be using the most stable and known baseline.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine whether Lighttpd has the latest approved security-relevant software updates installed. 

If the latest approved security-relevant software updates are not installed, this is a finding.'
  desc 'fix', 'Install the latest approved security-relevant software updates.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43507r667997_chk'
  tag severity: 'medium'
  tag gid: 'V-240274'
  tag rid: 'SV-240274r879827_rule'
  tag stig_id: 'VRAU-LI-000505'
  tag gtitle: 'SRG-APP-000456-WSR-000187'
  tag fix_id: 'F-43466r667998_fix'
  tag 'documentable'
  tag legacy: ['SV-99973', 'V-89323']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
