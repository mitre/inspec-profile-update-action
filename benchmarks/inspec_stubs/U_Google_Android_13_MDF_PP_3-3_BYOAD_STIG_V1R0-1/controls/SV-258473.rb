control 'SV-258473' do
  title 'The Google Android 13 BYOAD must be configured to disable device cameras and/or microphones when brought into DOD facilities where mobile phone cameras and/or microphones are prohibited.'
  desc 'In some DOD operational environments, the use of the mobile device camera or microphone could lead to a security incident or compromise of DOD information. The System Administrator must have the capability to disable the mobile device camera and/or microphone based on mission needs. Alternatively, mobile devices with cameras or microphones that cannot be disabled must be prohibited from the facility by the ISSO/ISSM.

If BYOAD devices are brought into facilities where the AO has determined the risk of using mobile device cameras or microphones is unacceptable, this could lead to the exposure of sensitive DOD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify Google Android 13 BYOADs are prohibited in DOD facilities that prohibit mobile devices with cameras and microphones.

If for DOD sites that prohibit mobile devices with cameras and microphones, Google Android 13 BYOADs have not been prohibited from the facility by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'Do not allow Google Android 13 BYOADs in DOD facilities where mobile phone cameras and/or microphones are prohibited.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62213r929233_chk'
  tag severity: 'medium'
  tag gid: 'V-258473'
  tag rid: 'SV-258473r929235_rule'
  tag stig_id: 'GOOG-13-802300'
  tag gtitle: 'PP-BYO-000230'
  tag fix_id: 'F-62122r929234_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
