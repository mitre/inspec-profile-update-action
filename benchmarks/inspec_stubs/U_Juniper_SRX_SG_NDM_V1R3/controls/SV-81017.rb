control 'SV-81017' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort) the Juniper SRX Services Gateway must use the SHA1 or later protocol for password authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

The password format command is an optional command that specifies the hash algorithm used for authenticating passwords. The options are MD5, SHA1, or DES. SHA1 is recommended because it is a FIPS-approved algorithm and provides stronger security.'
  desc 'check', 'Verify the default local password enforces this requirement by entering the following in configuration mode.

[edit]
show system login password

If the password format is not set to SHA-1, this is a finding.'
  desc 'fix', 'Enter the configuration mode on the Juniper SRX, set the password option for the local user account of last resort using the following command. 

[edit]
set system login password format sha1'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67173r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66527'
  tag rid: 'SV-81017r1_rule'
  tag stig_id: 'JUSX-DM-000136'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-72603r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
