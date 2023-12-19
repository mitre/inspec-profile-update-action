control 'SV-4253' do
  title 'The /etc/lilo.conf file must have mode 0600 or less permissive.'
  desc 'File permissions greater than 0600 could allow a user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'check', 'Check /etc/lilo.conf permissions:

# ls –lL /etc/lilo.conf

If /etc/lilo.conf has a mode more permissive than 0600, then this is a finding.'
  desc 'fix', 'Change the mode of the lilo.conf file.
# chmod 0600 /etc/lilo.conf'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2077r2_chk'
  tag severity: 'high'
  tag gid: 'V-4253'
  tag rid: 'SV-4253r2_rule'
  tag stig_id: 'GEN000000-LNX00220'
  tag gtitle: 'GEN000000-LNX00220'
  tag fix_id: 'F-25798r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
end
