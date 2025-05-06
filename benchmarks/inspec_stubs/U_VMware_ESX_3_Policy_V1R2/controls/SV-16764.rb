control 'SV-16764' do
  title 'A third party firewall is configured on ESX Server.'
  desc 'Third party software and services should not be installed in the service console. The service console is not intended to support the operation of additional software or services beyond what is included in the default ESX installation. VMware does not support the addition of third party applications that have not been explicitly approved.'
  desc 'check', 'Ask the IAO/SA if any third party firewalls are installed on the ESX Server service console.  If the answer is yes, inquire as to what is installed.  If it is anything other than IPtables, this is a finding.'
  desc 'fix', 'Remove third party firewalls from the ESX Server service console.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15825'
  tag rid: 'SV-16764r1_rule'
  tag stig_id: 'ESX0330'
  tag gtitle: 'A 3rd party firewall is configured on ESX Server.'
  tag fix_id: 'F-15777r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
