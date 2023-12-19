control 'SV-234219' do
  title 'The FortiGate device must limit the number of logon and user sessions.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege and open a CLI console available from the GUI.
or
Connect via SSH.

Run the following command:
show full-configuration sys global | grep -i admin

Check the output of the following lines:
set admin-concurrent disable
set admin-login-max <number as defined by the organization>     

If set admin-concurrent is not set to disable, this is a finding.
If set admin-login-max is not set to a number defined by the organization, this is a finding. The default setting is 100.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege and open a CLI console available from the GUI.
or
Connect via SSH.

Execute the following commands:
config system global
set admin-concurrent disable
set admin-login-max <number defined by the organization>    
end

With the implementation of this requirement, the organization can limit each administrator to one active session and limit the total number of concurrent administrator sessions to a value deemed appropriate.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37404r917460_chk'
  tag severity: 'medium'
  tag gid: 'V-234219'
  tag rid: 'SV-234219r917462_rule'
  tag stig_id: 'FGFW-ND-000300'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-37369r917461_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
