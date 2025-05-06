control 'SV-77317' do
  title 'Riverbed Optimization System (RiOS) must not have unnecessary services and functions enabled.'
  desc 'Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of Riverbed Optimization System (RiOS) version 8.x.x. Multiple application proxies can be installed on many ALGs. However, proxy types must be limited to related functions. At a minimum, the web and email gateway represent different security domains/trust levels. Organizations should also consider separation of gateways that service the DMZ and the trusted network.'
  desc 'check', 'Verify that the Riverbed Optimization System (RiOS) is configured to disable unrelated or unneeded application proxy services.

Obtain documentation for which applications are approved/disapproved for optimization by the organization.

Navigate to the device Management Console
Navigate to Optimize >> Optimization

Verify that the approved or disapproved applications are enabled or disabled according to organization requirements.

If optimization features are not enabled or disabled according to the organizations requirements, this is a finding.'
  desc 'fix', 'Check to see if services other than the authorized services are enabled for optimization.

Obtain documentation for which applications are approved/disapproved for optimization by the organization.

Navigate to the device Management Console
Navigate to Optimize >> Optimization

Set the approved or disapproved applications to enabled or disabled according to organization requirements.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63621r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62827'
  tag rid: 'SV-77317r1_rule'
  tag stig_id: 'RICX-AG-000087'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-68745r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
