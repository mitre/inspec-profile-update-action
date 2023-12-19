control 'SV-215293' do
  title 'AIX must setup SSH daemon to disable revoked public keys.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', 'If public keys are not used for SSH authentication, this is Not Applicable.

Run the following command:

# grep "^RevokedKeys" /etc/ssh/sshd_config
RevokedKeys     /etc/ssh/RevokedKeys.txt

If the command does not find the "RevokedKeys" setting, or the value for "RevokedKeys" is set to "none", this is a finding.'
  desc 'fix', 'Obtain the file that contains all the public keys that need to be revoked from ISSO/SA and save the file in /etc/ssh/ directory.
 
Edit the "/etc/ssh/sshd_config" file to allow "RevokedKeys" to point to the revoked key file obtained above.

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16491r294330_chk'
  tag severity: 'medium'
  tag gid: 'V-215293'
  tag rid: 'SV-215293r508663_rule'
  tag stig_id: 'AIX7-00-002110'
  tag gtitle: 'SRG-OS-000384-GPOS-00167'
  tag fix_id: 'F-16489r294331_fix'
  tag 'documentable'
  tag legacy: ['V-91549', 'SV-101647']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
