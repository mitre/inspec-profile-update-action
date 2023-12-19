control 'SV-223266' do
  title 'For environments requiring an Internet-facing capability, the SharePoint application server upon which Central Administration is installed, must not be installed in the DMZ.'
  desc 'Information flow control regulates where information is allowed to travel within an information system and between information systems (as opposed to who is allowed to access the information) and without explicit regard to subsequent accesses to the information. 

SharePoint installed Central Administrator is a powerful management tool used to administer the farm. This server should be installed on a trusted network segment. This server should also be used to run services rather than user-oriented web applications.'
  desc 'check', 'For environments requiring an Internet-facing capability, ensure the SharePoint Central Administration application server is not in the DMZ.

Inspect the logical location of the server farm web front end servers.

Verify the Central Administration site is not installed on a server located in a DMZ or other publicly accessible segment of the network.

If Central Administrator is installed on a publicly facing SharePoint server, this is a finding.'
  desc 'fix', 'For environments requiring an Internet-facing capability, remove the SharePoint Central Administration application server upon which Central Administration is installed from the DMZ.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24939r430855_chk'
  tag severity: 'medium'
  tag gid: 'V-223266'
  tag rid: 'SV-223266r612235_rule'
  tag stig_id: 'SP13-00-000155'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-24927r430856_fix'
  tag 'documentable'
  tag legacy: ['V-59995', 'SV-74425']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
