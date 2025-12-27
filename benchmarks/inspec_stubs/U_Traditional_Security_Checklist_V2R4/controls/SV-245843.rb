control 'SV-245843' do
  title 'Controlled Unclassified Information (CUI) - Employee Education and Training'
  desc 'Failure to handle CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure A, Paragraph 11, Enclosure B, paragraph 4.h & 6.m., and Enclosure C, paragraph 5.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AT-1, AT-2, AT-3 and AT-4.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 5.

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI); Enclosure 4.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 3.'
  desc 'check', 'General Policy Guidance:  At a minimum, DoD civilians, military members and on-site support contractors with access to CUI shall receive both initial and annual refresher training that reinforces the policies, principles, and procedures covered in CUI policy. Refresher training shall also address the threat and the techniques foreign intelligence activities use while attempting to obtain controlled unclassified DoD information and advise personnel of penalties for unauthorized disclosures. The importance of unclassified information, its potential sensitivity, and the requirement to have all information reviewed and approved for release prior to public disclosure or Web posting shall be reiterated. Refresher training shall also address relevant changes in CUI policy or procedures and issues or concerns identified during DoD Component oversight reviews.                                

Checks:

Check #1. Reviewers must check for an initial orientation on handling of CUI during new employee in-processing 

Check #2. Check that Annual Refresher training includes the topic of CUI as provided in the general policy guidance.  Check a sample number of individual training records and Annual Training briefing slides/materials for evidence of CUI training.   

Lack of either initial orientation or refresher training or both is a finding.                                    

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where training and associated documentation should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', 'General Policy Guidance:  At a minimum, DoD civilians, military members and on-site support contractors with access to CUI shall receive both initial and annual refresher training that reinforces the policies, principles, and procedures covered in CUI policy. Refresher training shall also address the threat and the techniques foreign intelligence activities use while attempting to obtain controlled unclassified DoD information and advise personnel of penalties for unauthorized disclosures. The importance of unclassified information, its potential sensitivity, and the requirement to have all information reviewed and approved for release prior to public disclosure or Web posting shall be reiterated. Refresher training shall also address relevant changes in CUI policy or procedures and issues or concerns identified during DoD Component oversight reviews.                                

Fix:

Ensure an initial orientation on handling of CUI is included during new employee in-processing and that Annual Refresher training includes the topic of CUI as provided in the general policy guidance.  Ensure that all initial and refresher training is documented.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49274r822906_chk'
  tag severity: 'medium'
  tag gid: 'V-245843'
  tag rid: 'SV-245843r822908_rule'
  tag stig_id: 'IS-16.02.01'
  tag gtitle: 'IS-16.02.01'
  tag fix_id: 'F-49229r822907_fix'
  tag 'documentable'
  tag legacy: ['SV-42476r3_rule', 'V-32159']
end
