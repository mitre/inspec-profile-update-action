control 'SV-255240' do
  title 'SSMC must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify that SSMC enforces a delay of at least four seconds between logon prompts following a failed logon attempt. To do so, perform the following steps.

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o config_failedlogin_delay -a status

Failed login delay is enabled

If the command output does not read "Failed login delay is enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to enforce a delay of at least four seconds between logon prompts following a failed logon attempt. To do so, perform the following steps.

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o config_failedlogin_delay -a enable -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58853r869868_chk'
  tag severity: 'medium'
  tag gid: 'V-255240'
  tag rid: 'SV-255240r869870_rule'
  tag stig_id: 'SSMC-OS-010060'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-58797r869869_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
