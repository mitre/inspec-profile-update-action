control 'SV-250597' do
  title 'The SSH daemon must not accept environment variables from the client or must only accept those pertaining to locale.'
  desc "Environment variables can be used to change the behavior of remote sessions and should be limited. Locale environment variables that specify the language, character set, and other features modifying the operation of software to match the user's preferences."
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep AcceptEnv /etc/ssh/sshd_config

If the "AcceptEnv" attribute is not set to "LOCALE" or unassigned (the "AcceptEnv" attribute minus any parameter assignment), this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"AcceptEnv LOCALE" 
or 
"AcceptEnv"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54032r798788_chk'
  tag severity: 'medium'
  tag gid: 'V-250597'
  tag rid: 'SV-250597r798790_rule'
  tag stig_id: 'GEN005528-ESXI5-000106'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53986r798789_fix'
  tag 'documentable'
  tag legacy: ['V-39266', 'SV-51082']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
