control 'SV-234168' do
  title 'The FortiGate device must enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Confirm the output from the following command:
     # show full-configuration system global | grep -i admin-lockout
The output should be:          
          set admin-lockout-duration 900
          set admin-lockout-threshold 3

If the admin-lockout-duration is not set to 900 and admin-lockout-threshold is not set to 3, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following commands:
     # config system global
     # set admin-lockout-duration 900
     # set admin-lockout-threshold 3
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37353r611691_chk'
  tag severity: 'medium'
  tag gid: 'V-234168'
  tag rid: 'SV-234168r611693_rule'
  tag stig_id: 'FGFW-ND-000045'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-37318r611692_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
