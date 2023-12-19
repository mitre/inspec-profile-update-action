control 'SV-55778' do
  title 'ISDN-based VTC equipment supporting secure (classified) and non-secure (unclassified) conferences which implement dial isolators and A/B switches must meet minimum port-to-port isolation standards.'
  desc 'ISDN-based VTC system A/B switches, Dial Isolators, and/or other devices used to interface between RED and BLACK circuits/equipment shall exhibit the following port-to-port isolation characteristics, as applicable:
• 100 dB over the baseband audio frequency range between 0.3 and 15 kHz.
• 80 dB over the baseband video frequency range up to 5 MHz.
• 60 dB over the frequency range from one times (Rd) to ten times the basic data rate (10Rd) of the digital signal(s) processed.

DISN Video Services (DVS) maintains a list of A/B switches and Dial Isolators that have been TEMPEST certified to meet the above requirements at http://disa.mil/Services/Network-Services/Video/~/media/Files/DISA/Services/DVS/red_black_peripherals.xls'
  desc 'check', 'Review documentation to determine whether approved dial isolators and A/B switches are being used. DISN Video Services (DVS) maintains a list of A/B switches and dial isolators that have been TEMPEST certified to meet the above requirements at http://disa.mil/Services/Network-Services/Video/~/media/Files/DISA/Services/DVS/red_black_peripherals.xls.
If the A/B switch or dial isolator is not on the list, this is a finding.'
  desc 'fix', 'Obtain and install DVS-approved dial isolators and A/B switches that maintain the following port-to-port isolation standards: 
• 100 dB over the baseband audio frequency range between 0.3 and 15 kHz.
• 80 dB over the baseband video frequency range up to 5 MHz.
• 60 dB over the frequency range from one times (Rd) to ten times the basic data rate (10Rd) of the digital signal(s) processed.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49193r6_chk'
  tag severity: 'medium'
  tag gid: 'V-43049'
  tag rid: 'SV-55778r1_rule'
  tag stig_id: 'RTS-VTC 7420'
  tag gtitle: 'RTS-VTC 7420 [ISDN]'
  tag fix_id: 'F-48626r6_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECTC-1'
end
