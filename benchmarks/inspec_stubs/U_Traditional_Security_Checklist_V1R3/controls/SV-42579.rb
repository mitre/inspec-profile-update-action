control 'SV-42579' do
  title 'Controlled Unclassified Information - Marking/Labeling Media within Unclassified Environments (Not Mixed with Classified)'
  desc 'Failure to mark CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure A, paragraph 6.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-3.

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI); Enclosure 3, paragraphs 1.d, 2.b., 2.c., 3.b., 4.c., 6.a(2) and 6.b.(2).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 4 and Chapter 8, Section 3, paragraph 8-302.g.(1).'
  desc 'check', 'General Information:

This check is only for unclassified/sensitive media being used in a strictly unclassified physical environment.  If all Controlled Unclassified Information (CUI) media are in a mixed environment where classified systems and media are in use, then STIG ID  IS-3.2.1. applies and this check is NA. 

Check to ensure the following standard is met: 

Regardless of media type, the requirement to identify as clearly as possible the information requiring protection remains. Therefore check to ensure that all unclassified media containing CUI is properly marked according to content. Where it is not feasible to include markings with all of the information required for classified or sensitive documents or media, an explanatory statement that provides the required information shall be included on the item or with the documentation that accompanies it.  

While For Official Use Only (FOUO) is the primary CUI marking used in DoD, all types of CUI markings must be considered for use as appropriate.  For instance: “Law Enforcement Sensitive” is a marking sometimes applied, in addition to the marking “FOR OFFICIAL USE ONLY,” by the Department of Justice and other activities in the law enforcement community, including those within the Department of Defense.   

TACTICAL ENVIRONMENT: The check is applicable for all fixed tactical processing environments where CUI is developed and used.  Not applicable to a field/mobile environment.'
  desc 'fix', 'General Information:

This fix is only for unclassified/sensitive media being used in a strictly unclassified physical environment.  If all Controlled Unclassified Information (CUI) media are in a mixed environment where classified systems and media are in use, then STIG ID  IS-3.2.1. applies and this potential vulnerability is NA. 

Ensure the following standard is met: 

Regardless of media type, the requirement to identify as clearly as possible the information requiring protection remains. Therefore ensure that all unclassified media containing CUI is properly marked according to content. Where it is not feasible to include markings with all of the information required for classified or sensitive documents or media, an explanatory statement that provides the required information shall be included on the item or with the documentation that accompanies it.  

While For Official Use Only (FOUO) is the primary CUI marking used in DoD, all types of CUI markings must be considered for use as appropriate.  For instance: “Law Enforcement Sensitive” is a marking sometimes applied, in addition to the marking “FOR OFFICIAL USE ONLY,” by the Department of Justice and other activities in the law enforcement community, including those within the Department of Defense.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40773r6_chk'
  tag severity: 'low'
  tag gid: 'V-32262'
  tag rid: 'SV-42579r3_rule'
  tag stig_id: 'IS-16.03.02'
  tag gtitle: 'Controlled Unclassified Information - Marking/Labeling Media'
  tag fix_id: 'F-36187r4_fix'
  tag 'documentable'
end
