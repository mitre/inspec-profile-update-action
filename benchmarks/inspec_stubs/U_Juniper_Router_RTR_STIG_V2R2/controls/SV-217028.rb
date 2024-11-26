control 'SV-217028' do
  title 'The Juniper router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.'
  desc 'The use of POTS lines to modems connecting to network devices provides clear text of authentication traffic over commercial circuits that could be captured and used to compromise the network. Additional war dial attacks on the device could degrade the device and the production network.

Secured modem devices must be able to authenticate users and must negotiate a key exchange before full encryption takes place. The modem will provide full encryption capability (Triple DES) or stronger. The technician who manages these devices will be authenticated using a key fob and granted access to the appropriate maintenance port; thus, the technician will gain access to the managed device (router, switch, etc.). The token provides a method of strong (two-factor) user authentication. The token works in conjunction with a server to generate one-time user passwords that will change values at second intervals. The user must know a personal identification number (PIN) and possess the token to be allowed access to the device.'
  desc 'check', 'Review the configuration and verify that the auxiliary port is disabled unless a secured modem providing encryption and authentication is connected to it.

If the auxiliary port has never been configured or has been removed from the configuration this is Not Applicable.

system {
    host-name XYZ;
    …
    …
    …
    ports {
        auxiliary {
            disable;
            type xterm;
        }
    }

If the auxiliary port is not disabled or is not connected to a secured modem when it is enabled, this is a finding.'
  desc 'fix', 'Disable the auxiliary port.

[edit system ports]
set auxiliary disable

Note: If used for out-of-band administrative access, the port must be connected to a secured modem providing encryption and authentication.'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18257r296952_chk'
  tag severity: 'low'
  tag gid: 'V-217028'
  tag rid: 'SV-217028r639663_rule'
  tag stig_id: 'JUNI-RT-000230'
  tag gtitle: 'SRG-NET-000019-RTR-000001'
  tag fix_id: 'F-18255r296953_fix'
  tag 'documentable'
  tag legacy: ['SV-101051', 'V-90841']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
