control 'SV-254119' do
  title 'Nutanix AOS must be running an operating system release that is currently supported by the vendor.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes) to production systems after thorough testing of the patches within a lab environment. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.'
  desc 'check', %q(1. Log in to the Prism Element web interface.
2. Click on the person's name that just logged in.
3. In the drop down menu, click "About Nutanix".
4. Compare the Nutanix AOS version against the supported versions in the Nutanix support portal.  
https://www.nutanix.com/support-services/product-support

If the AOS version is not supported as indicated in the Nutanix support portal, this is a finding.)
  desc 'fix', 'Use Nutanix LCM and upgrade to a supported version.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57604r846443_chk'
  tag severity: 'medium'
  tag gid: 'V-254119'
  tag rid: 'SV-254119r846445_rule'
  tag stig_id: 'NUTX-AP-001080'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-57555r846444_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
