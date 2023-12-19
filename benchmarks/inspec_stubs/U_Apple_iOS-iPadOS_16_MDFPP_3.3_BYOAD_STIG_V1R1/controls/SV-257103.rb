control 'SV-257103' do
  title 'The iOS/iPadOS 16 BYOAD must be configured to disable device cameras and/or microphones when brought into DOD facilities where mobile phone cameras and/or microphones are prohibited.'
  desc 'In some DOD operational environments, the use of the mobile device camera or microphone could lead to a security incident or compromise of DOD information. The system administrator must have the capability to disable the mobile device camera and/or microphone based on mission needs. Alternatively, mobile devices with cameras or microphones that cannot be disabled must be prohibited from the facility by the information system security officer (ISSO)/information system security manager (ISSM).

If BYOAD devices are brought into facilities where the authorizing official (AO) has determined the risk of using mobile device cameras or microphones is unacceptable, this could lead to the exposure of sensitive DOD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify iOS/iPadOS 16 BYOADs are prohibited in DOD facilities that prohibit mobile devices with cameras and microphones. 

Refer to the site Facility Security Standard Operating Procedure (SOP) to determine site requirements.

If for DOD sites that prohibit mobile devices with cameras and microphones, the ISSO/ISSM has not prohibited iOS/iPadOS 16 BYOADs from the facility, this is a finding.'
  desc 'fix', 'Do not allow iOS iPadOS 16 BYOADs in DOD facilities where mobile phone cameras and/or microphones are prohibited. 

Refer to the site Facility Security SOP to determine site requirements.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60788r904052_chk'
  tag severity: 'medium'
  tag gid: 'V-257103'
  tag rid: 'SV-257103r904054_rule'
  tag stig_id: 'AIOS-16-800230'
  tag gtitle: 'PP-BYO-000230'
  tag fix_id: 'F-60729r904053_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
