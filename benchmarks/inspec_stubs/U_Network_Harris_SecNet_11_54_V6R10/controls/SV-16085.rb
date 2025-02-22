control 'SV-16085' do
  title 'Any wireless technology used to transmit classified information must be an NSA Type 1 product.'
  desc 'NSA Type 1 certification provides the level of assurance required for transmission of classified data.  Systems without this certification are more likely to be compromised by a determined and resourceful adversary.'
  desc 'check', 'Visually verify the site is using a Harris Corporation SecNet 11 or SecNet 54 or L3 KOV-26 Talon (version 1.1.04 or later) for the classified WLAN.'
  desc 'fix', 'Immediately remove the uncertified device from the network. Install and operate a Type 1 product if wireless functionality is still required.'
  impact 0.7
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-13709r1_chk'
  tag severity: 'high'
  tag gid: 'V-15300'
  tag rid: 'SV-16085r1_rule'
  tag stig_id: 'WIR0205'
  tag gtitle: 'Classified WLAN uses NSA Type 1 products'
  tag fix_id: 'F-6728r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
end
