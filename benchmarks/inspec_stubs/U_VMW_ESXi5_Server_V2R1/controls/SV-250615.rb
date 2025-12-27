control 'SV-250615' do
  title 'The SSH daemon must limit connections to a single session.'
  desc 'The SSH protocol has the ability to provide multiple sessions over a single connection without reauthentication. A compromised client could use this feature to establish additional sessions to a system without consent or knowledge of the user.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep MaxSessions /etc/ssh/sshd_config

If the command returns nothing, or if "MaxSessions" is not set to "1", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"MaxSessions 1" 

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54050r798842_chk'
  tag severity: 'medium'
  tag gid: 'V-250615'
  tag rid: 'SV-250615r798844_rule'
  tag stig_id: 'SRG-OS-000027-ESXI5'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag fix_id: 'F-54004r798843_fix'
  tag 'documentable'
  tag legacy: ['V-39253', 'SV-51069']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
