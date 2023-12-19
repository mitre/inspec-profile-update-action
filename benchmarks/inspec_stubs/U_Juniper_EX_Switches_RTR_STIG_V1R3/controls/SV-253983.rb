control 'SV-253983' do
  title 'The Juniper router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.'
  desc 'The use of POTS lines to modems connecting to network devices provides clear text of authentication traffic over commercial circuits that could be captured and used to compromise the network. Additional war dial attacks on the device could degrade the device and the production network.

Secured modem devices must be able to authenticate users and must negotiate a key exchange before full encryption takes place. The modem will provide full encryption capability (Triple DES) or stronger. The technician who manages these devices will be authenticated using an authorized MFA token and granted access to the appropriate maintenance port; thus, the technician will gain access to the managed device (router, switch, etc.). The token provides a method of strong (two-factor) user authentication. The token works in conjunction with a server to generate one-time user passwords. The user must know a personal identification number (PIN) and possess the token to be allowed access to the device.'
  desc 'check', 'Review the configuration and verify that the auxiliary port is disabled unless a secured modem providing encryption and authentication is connected to it.

The Junos auxiliary port is disabled by default. Verify the auxiliary port is not configured (there will be no [edit system ports auxiliary] stanza) or that the auxiliary port is explicitly disabled.

[edit system ports]
auxiliary {
    disable;
}

If the auxiliary port is not disabled or is not connected to a secured modem when it is enabled, this is a finding.'
  desc 'fix', 'Disable the auxiliary port.

set system ports auxiliary disable
-or-
delete system ports auxiliary

If used for out-of-band administrative access, the port must be connected to a secured modem providing encryption and authentication.'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57435r843980_chk'
  tag severity: 'low'
  tag gid: 'V-253983'
  tag rid: 'SV-253983r843982_rule'
  tag stig_id: 'JUEX-RT-000110'
  tag gtitle: 'SRG-NET-000019-RTR-000001'
  tag fix_id: 'F-57386r843981_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
