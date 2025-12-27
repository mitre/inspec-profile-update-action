control 'SV-44791' do
  title 'Direct logins must not be permitted to shared, default, application, or utility accounts.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide identification and authentication.  There is no way to provide for non-repudiation or individual accountability.'
  desc 'check', 'Use the last command to check for multiple accesses to an account from different workstations/IP addresses.

# last -R

If users log directly onto accounts, rather than using the switch user (su) command from their own named account to access them, this is a finding (such as logging directly on to oracle).

Verify with the SA or the IAO on documentation for users/administrators to log into their own accounts first and then switch user (su) to the account to be shared has been maintained including requirements and procedures. If no such documentation exists, this is a finding.'
  desc 'fix', 'Use the switch user (su) command from a named account login to access shared accounts. Maintain audit trails to identify the actual user of the account name. Document requirements and procedures for users/administrators to log into their own accounts first and then switch user (su) to the account to be shared.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42288r1_chk'
  tag severity: 'medium'
  tag gid: 'V-760'
  tag rid: 'SV-44791r1_rule'
  tag stig_id: 'GEN000280'
  tag gtitle: 'GEN000280'
  tag fix_id: 'F-38241r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
