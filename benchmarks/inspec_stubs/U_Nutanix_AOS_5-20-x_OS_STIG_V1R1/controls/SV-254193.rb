control 'SV-254193' do
  title 'Nutanix AOS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Confirm Nutanix AOS enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.

$ sudo grep -i fail_delay /etc/login.defs
FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to enforce a delay between logon prompts following a failed logon attempt by running the following command:

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57678r846665_chk'
  tag severity: 'medium'
  tag gid: 'V-254193'
  tag rid: 'SV-254193r846667_rule'
  tag stig_id: 'NUTX-OS-001060'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-57629r846666_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
