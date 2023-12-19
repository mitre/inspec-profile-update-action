control 'SV-7365' do
  title 'The auxiliary port must be disabled unless it is connected to a secured modem providing encryption and authentication.'
  desc 'The use of POTS lines to modems connecting to network devices provides clear text of authentication traffic over commercial circuits that could be captured and used to compromise the network.  Additional war dial attacks on the device could degrade the device and the production network.

Secured modem devices must be able to authenticate users and must negotiate a key exchange before full encryption takes place.  The modem will provide full encryption capability (Triple DES) or stronger.  The technician who manages these devices will be authenticated using a key fob and granted access to the appropriate maintenance port, thus the technician will gain access to the managed device (router, switch, etc.).  The token provides a method of strong (two-factor) user authentication.  The token works in conjunction with a server to generate one-time user passwords that will change values at second intervals.  The user must know a personal identification number (PIN) and possess the token to be allowed access to the device.'
  desc 'check', 'Review the configuration and verify the auxiliary port is disabled unless a secured modem providing encryption and authentication is connected.

If the auxiliary port is enabled without the use of a secured modem, this is a finding.'
  desc 'fix', 'Disable the auxiliary port. If used for out-of-band administrative access, the port must be connected to a secured modem providing encryption and authentication.'
  impact 0.3
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3513r5_chk'
  tag severity: 'low'
  tag gid: 'V-7011'
  tag rid: 'SV-7365r4_rule'
  tag stig_id: 'NET1629'
  tag gtitle: 'The auxiliary port is not disabled.'
  tag fix_id: 'F-6614r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
