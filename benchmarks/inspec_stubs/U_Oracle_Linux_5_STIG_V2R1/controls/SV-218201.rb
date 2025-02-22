control 'SV-218201' do
  title 'Direct logins must not be permitted to shared, default, application, or utility accounts.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide identification and authentication.  There is no way to provide for non-repudiation or individual accountability.'
  desc 'check', 'Use the last command to check for multiple accesses to an account from different workstations/IP addresses.

# last -w

If users log directly on to accounts, rather than using the switch user (su) command from their own named account to access them, this is a finding (such as logging directly onto oracle).

Verify with the SA or the ISSO on documentation for users/administrators to log on to their own accounts first and then switch user (su) to the account to be shared has been maintained, including requirements and procedures. If no such documentation exists, this is a finding.'
  desc 'fix', 'Use the switch user (su) command from a named account login to access shared accounts. Document requirements and procedures for users/administrators to log into their own accounts first and then switch user (su) to the account to be shared.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19676r553940_chk'
  tag severity: 'medium'
  tag gid: 'V-218201'
  tag rid: 'SV-218201r603259_rule'
  tag stig_id: 'GEN000280'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-19674r553941_fix'
  tag 'documentable'
  tag legacy: ['V-760', 'SV-63187']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
