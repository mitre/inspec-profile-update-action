control 'SV-234221' do
  title 'The FortiGate device must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system password-policy | grep -i change
    The output should be:
      # set change-4-characters enable

If the change-4-characters parameter is set to disable, this is a finding.

If the change-4-characters parameter is set to enable, this mitigates to a CAT III finding, as this is a mitigation to at least changing four characters when changing the account of last resort. This is a limitation of the device. It is not possible to mitigate to "Not A Finding".'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system password-policy
           # set change-4-characters enable
     # end

Note that this setting only mitigates the requirement to a CAT III finding, as this is a mitigation to change at least four characters when changing the account of last resort. This is a limitation of the device. It is not possible to mitigate to "Not A Finding".'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37406r628891_chk'
  tag severity: 'medium'
  tag gid: 'V-234221'
  tag rid: 'SV-234221r879607_rule'
  tag stig_id: 'FGFW-ND-000311'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-37371r611851_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
