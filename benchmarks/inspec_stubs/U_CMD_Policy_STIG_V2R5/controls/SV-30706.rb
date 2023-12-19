control 'SV-30706' do
  title 'Required actions must be followed at the site when a CMD has been lost or stolen.'
  desc 'If procedures for lost or stolen CMDs are not followed, it is more likely that an adversary could obtain the device and use it to access DoD networks or otherwise compromise DoD IA.'
  desc 'check', 'Interview the ISSO. Determine if any site mobile devices were reported lost or stolen within the previous 24 months. If yes, review written records, incident reports, and/or after action reports and determine if required procedures were followed. 

If the site had a lost or stolen mobile device within the previous 24 months and required procedures were not followed, this is a finding.'
  desc 'fix', 'Follow required actions when a CMD is reported lost or stolen.'
  impact 0.3
  ref 'DPMS Target Smartphone Handheld Policy'
  tag check_id: 'C-31133r4_chk'
  tag severity: 'low'
  tag gid: 'V-24969'
  tag rid: 'SV-30706r5_rule'
  tag stig_id: 'WIR-SPP-007-02'
  tag gtitle: 'Follow lost/stolen CMD procedures'
  tag fix_id: 'F-27592r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
