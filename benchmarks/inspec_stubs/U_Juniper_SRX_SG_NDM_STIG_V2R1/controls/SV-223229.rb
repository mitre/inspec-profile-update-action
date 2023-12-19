control 'SV-223229' do
  title 'The Juniper SRX Services Gateway must immediately terminate SSH network connections when the user logs off, the session abnormally terminates, or an upstream link from the managed device goes down.'
  desc 'This setting frees device resources and mitigates the risk of an unauthorized user gaining access to an open idle session. 

When sessions are terminated by a normal administrator log off, the Juniper SRX makes the current contents unreadable and no user activity can take place in the session. However, abnormal terminations or loss of communications do not signal a session termination, thus a keep-alive count and interval must be configured so the device will know when communication with the client is no longer available. The keep-alive value and the interval between keep-alive messages must be set to an organization-defined value based on mission requirements and network performance.'
  desc 'check', '[edit]
show system services ssh

If the keep-alive count and keep-alive interval are not set to an organization-defined value, this is a finding.'
  desc 'fix', 'Configure the SSH keep-alive value.

[edit]
set system services ssh client-alive-count-max <organization-defined value>
set system services ssh client-alive-interval <organization-defined value>

Note: The keep-alive value and the interval between keep-alive messages must be set based on mission requirements and network performance for each local network.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24902r513374_chk'
  tag severity: 'medium'
  tag gid: 'V-223229'
  tag rid: 'SV-223229r513376_rule'
  tag stig_id: 'JUSX-DM-000153'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-24890r513375_fix'
  tag 'documentable'
  tag legacy: ['SV-81025', 'V-66535']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
