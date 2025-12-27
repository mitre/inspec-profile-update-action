control 'SV-250616' do
  title 'The operating system must use cryptography to protect the confidentiality of remote access sessions.'
  desc 'Remote network access is accomplished by leveraging common communication protocols and establishing a remote connection. These connections will occur over the public Internet. 

Remote access is any access to an organizational information system by a user (or an information system) communicating through an external, non-organization-controlled network (e.g., the Internet). Examples of remote access methods include dial-up, broadband, and wireless. 

Using cryptography ensures confidentiality of the remote access connections.'
  desc 'check', %q(Disable lock down mode.
Enable the ESXi Shell.

Check the SSH daemon configuration for required protocol. # grep -i "Protocol 2" /etc/ssh/sshd_config | grep -v '^#' 

Re-enable lock down mode.

If no lines are returned, or the returned protocol list contains anything except 2, this is a finding.)
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH daemon configuration and add/modify the "Protocol" configuration for Protocol 2 only. 
# vi /etc/ssh/sshd_config

Re-enable lock down mode.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54051r798845_chk'
  tag severity: 'high'
  tag gid: 'V-250616'
  tag rid: 'SV-250616r798847_rule'
  tag stig_id: 'SRG-OS-000033-ESXI5'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-54005r798846_fix'
  tag 'documentable'
  tag legacy: ['SV-51269', 'V-39411']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
