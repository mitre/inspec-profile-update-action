control 'SV-42581' do
  title 'Controlled Unclassified Information - Transmission by either Physical or Electronic Means'
  desc 'Failure to handle/transmit CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

NIST FIPS 140-2, Security Requirements for Cryptographic Modules

DODI 8520.2, “Public Key Infrastructure (PKI) and Public Key Enabling (PKE)”

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure A, paragraphs 13.a., 13.b.(2)(3), and Enclosure C, paragraphs 22.d,, 25.a.,d.,e.,f., 26.j.(2), and 35.a. 

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-17, AC-20, IA-2, SC-8, SC-9, and SC-23.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 7, paragraph 13.

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI); Enclosure 3., paragraphs 2.e.(2), 4.d.(1), 4.e.(1)(2), 5.d.(2), and 6.b.(4)(a)&(b).'
  desc 'check', 'General Information:

Standards for transmission for most types of CUI are the same as for FOUO but some variance does exist.  Therefore, specific requirements for certain CUI may need to be checked against applicable references to ensure proper means for transmission are used.  

For most CUI and FOUO specifically check to ensure the following standards are met:  

1.  FOUO information and material may be transmitted via first class mail, parcel post, or, for bulk shipments, via fourth class mail. 

2.  Electronic transmission of FOUO information, e.g., e-mail, shall be by approved secure communications systems or systems utilizing other protective measures such as Public Key Infrastructure (PKI) or transport layer security (e.g., https). 

3.  Use of wireless telephones (cell phones, wireless hand held phones, bluetooth, etc.) should be avoided when other options are available. 

4.  Transmission of FOUO by facsimile machine (fax) is permitted; the sender is responsible for determining that appropriate protection will be available at the receiving location prior to transmission (e.g., machine attended by a person authorized to receive FOUO; fax located in a controlled government environment).                                    

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', 'General Information:

Standards for transmission for most types of CUI are the same as for FOUO but some variance does exist.  Therefore, specific requirements for certain CUI may need to be checked against applicable references to ensure proper means for transmission are used.  

For most CUI and FOUO specifically ensure the following standards are met:  

1.  FOUO information and material may be transmitted via first class mail, parcel post, or, for bulk shipments, via fourth class mail. 

2.  Electronic transmission of FOUO information, e.g., e-mail, shall be by approved secure communications systems or systems utilizing other protective measures such as Public Key Infrastructure (PKI) or transport layer security (e.g., https). 

3.  Use of wireless telephones (cell phones, wireless hand held phones, bluetooth, etc.) should be avoided when other options are available. 

4.  Transmission of FOUO by facsimile machine (fax) is permitted; the sender is responsible for determining that appropriate protection will be available at the receiving location prior to transmission (e.g., machine attended by a person authorized to receive FOUO; fax located in a controlled government environment).'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40775r8_chk'
  tag severity: 'medium'
  tag gid: 'V-32264'
  tag rid: 'SV-42581r3_rule'
  tag stig_id: 'IS-16.02.05'
  tag gtitle: 'Controlled Unclassified Information - Transmission'
  tag fix_id: 'F-36189r4_fix'
  tag 'documentable'
end
