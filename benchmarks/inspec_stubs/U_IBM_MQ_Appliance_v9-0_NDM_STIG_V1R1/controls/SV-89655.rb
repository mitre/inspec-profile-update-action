control 'SV-89655' do
  title 'The MQ Appliance network device must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers. 

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. 

This requirement is applicable to devices that use a web interface for MQ Appliance device management.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
config 
crypto 
show crypto-mode 

If the result is not fips-140-2-l1, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. Enable FIPS 140-2 Level 1 mode at the next reload of the firmware. 

Enter: 
config 
crypto 
crypto-mode-set fips-140-2-l1 

The following message will appear: 
"Crypto Mode Successfully set to fips-140-2-l1 for next boot." 

Reboot MQ appliance.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74981'
  tag rid: 'SV-89655r1_rule'
  tag stig_id: 'MQMH-ND-000790'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-81597r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
