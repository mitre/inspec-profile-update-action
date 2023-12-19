control 'SV-237341' do
  title 'The ArcGIS Server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Review the ArcGIS Server configuration to ensure it is deployed onto a Windows 2008 R2 or Windows 2012 R2 Active Directory Member server upon which the Windows Server 2012/2012 R2 Member Server Security Technical Implementation Guide or Windows Server 2008 R2 Member Server Security Technical Implementation Guide has been applied (respectively).

If the server on which ArcGIS Server is deployed is not a Windows 2008 R2 or Windows 2012 R2 Active Directory member server which has the Windows Server 2012/2012 R2 Member Server Security Technical Implementation Guide or Windows Server 2008 R2 Member Server Security Technical Implementation Guide has been applied (respectively), this is a finding.'
  desc 'fix', 'Deploy ArcGIS Server onto a Windows 2008 R2 or Windows 2012 R2 Active Directory Member server that aligns to the Windows Server 2012/2012 R2 Member Server Security Technical Implementation Guide or Windows Server 2008 R2 Member Server Security Technical Implementation Guide (respectively).'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40560r642840_chk'
  tag severity: 'medium'
  tag gid: 'V-237341'
  tag rid: 'SV-237341r879887_rule'
  tag stig_id: 'AGIS-00-000247'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-40523r642841_fix'
  tag 'documentable'
  tag legacy: ['SV-80059', 'V-65569']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
