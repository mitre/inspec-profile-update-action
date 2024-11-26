control 'SV-214175' do
  title 'Infoblox DNS servers must be configured to protect the authenticity of communications sessions for dynamic updates.'
  desc 'DNS is a fundamental network service that is prone to various attacks, such as cache poisoning and man-in-the middle attacks. If communication sessions are not provided appropriate validity protections, such as the employment of DNSSEC, the authenticity of the data cannot be guaranteed.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Infoblox Systems can be configured in two ways to limit DDNS client updates. 

For clients that support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.
Select each server, click "Edit", toggle Advanced Mode and select GSS-TSIG.
Verify that "Enable GSS-TSIG authentication of clients" is enabled.

For clients that do not support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled. Select each server, click "Edit".
Select the "Updates" tab. 

Verify that either a Named ACL or Set of ACEs are defined to limit client DDNS. When complete, click "Cancel" to exit the "Properties" screen.

If clients that support GSS-TSIG do not have "Enable GSS-TSIG authentication of clients" set or a named ACL or set of ACEs for clients that do not support GSS-TSIG, this is a finding.'
  desc 'fix', 'Infoblox Systems can be configured in two ways to limit DDNS client updates. 

For clients that support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled. 
Select each server, click "Edit", toggle Advanced Mode and select GSS-TSIG.
Configure the option "Enable GSS-TSIG authentication of clients".
Upload the required keys. Refer to the Administration Guide for detailed instructions.

For clients that do not support GSS-TSIG, navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.
Select each server, click "Edit".
Select the "Updates" tab.
Select either an existing Named ACL or configure a new Set of ACEs to limit client DDNS.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15390r295788_chk'
  tag severity: 'medium'
  tag gid: 'V-214175'
  tag rid: 'SV-214175r612370_rule'
  tag stig_id: 'IDNS-7X-000280'
  tag gtitle: 'SRG-APP-000219-DNS-000029'
  tag fix_id: 'F-15388r295789_fix'
  tag 'documentable'
  tag legacy: ['V-68547', 'SV-83037']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
