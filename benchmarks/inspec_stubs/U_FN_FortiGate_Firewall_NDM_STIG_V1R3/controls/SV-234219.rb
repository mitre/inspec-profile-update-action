control 'SV-234219' do
  title 'The FortiGate device must limit the number of logon and user sessions.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console available from the GUI.
2. Run the following commands:
# show full-configuration sys global | grep -i admin

The output should contain;
     set admin-concurrent disable
    set admin-login-max 3     

If set admin-concurrent is not set to disable, this is a finding.
If set admin-login-max is not set to three, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console available from the GUI.
2. Run the following commands:
# config system global
#     set admin-concurrent disable
#     set admin-login-max 3     
# end

With the implementation of this requirement, the organization can limit each administrator to one active setting and limit the total number of concurrent administrators to three.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37404r611844_chk'
  tag severity: 'medium'
  tag gid: 'V-234219'
  tag rid: 'SV-234219r611846_rule'
  tag stig_id: 'FGFW-ND-000300'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-37369r611845_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
