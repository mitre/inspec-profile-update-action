control 'SV-234215' do
  title 'The FortiGate device must generate unique session identifiers using a FIPS 140-2-approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement is applicable to devices that use a web interface for device management.'
  desc 'check', 'Session IDs are generated using the FIPS random generator if the device is in FIPS mode.

To verify login to the FortiGate GUI with Super-Admin privilege:

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # get system status | grep -i fips
The output should be:         
             FIPS-CC mode: enable

If FIPS-CC mode parameter is not set to enable, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
      # config system fips-cc
            # set status enable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37400r628883_chk'
  tag severity: 'medium'
  tag gid: 'V-234215'
  tag rid: 'SV-234215r628884_rule'
  tag stig_id: 'FGFW-ND-000280'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-37365r611833_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
