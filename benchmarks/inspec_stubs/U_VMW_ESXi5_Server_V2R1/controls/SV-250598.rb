control 'SV-250598' do
  title 'The SSH client must not send environment variables to the server or must only send those pertaining to locale.'
  desc "Environment variables can be used to change the behavior of remote sessions and should be limited. Locale environment variables specify the language, character set, and other features modifying the operation of software to match the user's preferences."
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep SendEnv /etc/ssh/ssh_config

If the "SendEnv" attribute is not set to "LOCALE", this is a finding. If the /etc/ssh/ssh_config file does not exist or the SendEnv option is not set, this is not a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/ssh_config

Add/modify the attribute line entry to one of the following (quotes for emphasis only):
"SendEnv LOCALE " 
or 
"SendEnv"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54033r798791_chk'
  tag severity: 'medium'
  tag gid: 'V-250598'
  tag rid: 'SV-250598r798793_rule'
  tag stig_id: 'GEN005529-ESXI5-708'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53987r798792_fix'
  tag 'documentable'
  tag legacy: ['SV-51085', 'V-39269']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
