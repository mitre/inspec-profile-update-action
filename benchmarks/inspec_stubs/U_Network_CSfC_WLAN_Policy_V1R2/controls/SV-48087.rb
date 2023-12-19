control 'SV-48087' do
  title 'The site must successfully complete a security assessment of the CSfC based campus WLAN system to confirm compliance with the CSfC Campus WLAN Capability Package prior to IOC and yearly thereafter.'
  desc 'Classified data could be exposed if the campus WLAN system is operated out of compliance with the Commercial Solutions for Classified (CSfC) Campus IEEE 802.11 Wireless Local Area Network (WLAN) Capability Package and any NSA approved deviations to the capability package. The NSA Commercial Solutions for Classified (CSfC) registration process requires CSfC-listed equipment be used in the campus WLAN system. The site should perform a security assessment prior to operating the system to confirm it is compliant and periodically, thereafter, to verify the system is still in compliance with the most recent version of the capability package.'
  desc 'check', 'The security assessment must validate that the site’s CSfC based campus WLAN system is compliant with all technical and non-technical requirements listed in the CSfC Campus IEEE 802.11 Wireless Local Area Network (WLAN) Capability Package. The assessment should be successfully completed (no findings) before the systems Initial Operating Capability (IOC) is achieved and yearly thereafter. It is recommended that the assessment be completed by an organization that is separate from the organization that is setting up and managing the campus WLAN system.

-Review the registration agreement between the site and NSA to determine if any deviations from the Campus WLAN Capability Package have been approved by NSA.

-Review security assessment reports from assessments completed before IOC or yearly thereafter and interview the site IAM/IAO. Determine the date of the last assessment and if there are any open findings from the report.

-If security assessments were not completed prior to IOC or yearly thereafter or if assessments were completed but there were open findings listed in the last report, this is a finding.'
  desc 'fix', 'Conduct security assessments of the campus WLAN system before IOC and yearly thereafter and immediately close any open findings or shut down the system.'
  impact 0.7
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-44826r2_chk'
  tag severity: 'high'
  tag gid: 'V-36590'
  tag rid: 'SV-48087r1_rule'
  tag stig_id: 'WIR-CWLAN-01'
  tag gtitle: 'Security assessment of campus WLAN system'
  tag fix_id: 'F-41227r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
  tag ia_controls: 'DCAR-1, DCII-1'
end
