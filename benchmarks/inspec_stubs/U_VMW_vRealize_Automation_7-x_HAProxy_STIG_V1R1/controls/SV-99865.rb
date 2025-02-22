control 'SV-99865' do
  title 'HAProxy must have the latest approved security-relevant software updates installed.'
  desc 'All vRA components, to include Lighttpd, are under VMware configuration management control. The CM process ensures that all patches, functions, and modules have been thoroughly tested before being introduced into the production version.

By using the most current version of Lighttpd, the Lighttpd server will always be using the most stable and known baseline.'
  desc 'check', 'Interview the ISSO.

Determine whether HAProxy has the latest approved security-relevant software updates and updates are installed within the identified time period. 

If the latest approved security-relevant software updates are not installed or installed within the identified time period, this is a finding.'
  desc 'fix', 'Ensure HAProxy has the latest approved security-relevant software updates and the updates are installed within the identified time period.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89215'
  tag rid: 'SV-99865r1_rule'
  tag stig_id: 'VRAU-HA-000480'
  tag gtitle: 'SRG-APP-000456-WSR-000187'
  tag fix_id: 'F-95957r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
