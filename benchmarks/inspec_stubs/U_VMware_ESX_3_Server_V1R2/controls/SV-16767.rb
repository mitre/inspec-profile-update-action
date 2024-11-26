control 'SV-16767' do
  title 'ESX Server service console administrators are not documented'
  desc 'User access to the service console should be restricted.  The service console has privileged access to the ESX Server and only authorized users should be provided logon access.  Personnel that manage the ESX Server will have individual usernames for accessing the ESX Server, creating an audit trail of activities. Virtual machine users will not have ESX Server logins, since there is no inherent need.'
  desc 'check', 'Request the ESX Server service console user documentation from the IAO/SA. Compare this documentation to the users on the ESX Server by performing the following at the service console: 
# less /etc/passwd
If a discrepancy exists between the ESX Server and the documentation, this is a finding.'
  desc 'fix', 'Document all ESX Server service console users for the ESX Server.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16179r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15828'
  tag rid: 'SV-16767r1_rule'
  tag stig_id: 'ESX0360'
  tag gtitle: 'ESX service console users are not documented.'
  tag fix_id: 'F-15780r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
