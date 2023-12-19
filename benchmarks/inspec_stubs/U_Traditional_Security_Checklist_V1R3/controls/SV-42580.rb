control 'SV-42580' do
  title 'Controlled Unclassified Information - Encryption of Data at Rest'
  desc 'Failure to handle CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

DoD CIO Memorandum, Encryption of Sensitive Unclassified Data at Rest on Mobile Computing Devices and Removable Storage Media, 3 July 2007

NIST FIPS 140-2, Security Requirements for Cryptographic Modules

NSTISSI No. 11, National Policy Governing the Acquisition of Information Assurance (IA) and IA-Enabled Information Technology (IT) Products

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure A, paragraphs 6.b., 13.b.(2), 13.b.(3) and Enclosure C, paragraphs 21.f. and 21.g.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-5, PL-2 and SC-28.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 7, paragraphs 8. and 9.a.

DoD Instruction 8420.01, Commercial Wireless Local Area Network (WLAN) Devices, Systems, and Technologies, 3 November 2017, paragraphs 1.2.b., 1.2.h., 3.2.a., 3.2.a.(3), and 3.8.d.

NSA, Commercial Solutions for Classified Data at Rest Capability Package, current edition'
  desc 'check', 'Check to ensure the following standards concerning encryption of data-at-rest are met: 

In accordance with DoD policy, all unclassified DoD data that has not been approved for public release and is stored on mobile computing devices or removable storage media must be encrypted using commercially available encryption technology. This requirement includes all CUI as well as other unclassified information that has not been reviewed and approved for public release. This includes certain Personally Identifiable Information (PII). Examples of common devices requiring DAR encryption are laptops used for telework or TDY and mobile devices such as cellular phones, tablets, etc. approved for processing and storing DoD sensitive data, and CDs, thumb drives (flash media) DVDs and other removable media.

See ASD(NII) Memorandum, Encryption of Sensitive Unclassified Data at Rest on Mobile Computing Devices and Removable Storage Media, 3 Jul 07 for detailed guidance.
                                             
TACTICAL ENVIRONMENT: The check is applicable for all tactical processing environments.'
  desc 'fix', 'Ensure the following standards concerning encryption of data-at-rest are met: 

In accordance with DoD policy, all unclassified DoD data that has not been approved for public release and is stored on mobile computing devices or removable storage media must be encrypted using commercially available encryption technology. This requirement includes all CUI as well as other unclassified information that has not been reviewed and approved for public release. This includes certain Personally Identifiable Information (PII). Examples of common devices requiring DAR encryption are laptops used for telework or TDY and mobile devices such as cellular phones, tablets, etc. approved for processing and storing DoD sensitive data, and CDs, thumb drives (flash media) DVDs and other removable media.

See ASD(NII) Memorandum, Encryption of Sensitive Unclassified Data at Rest on Mobile Computing Devices and Removable Storage Media, 3 Jul 07 for detailed guidance.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40774r7_chk'
  tag severity: 'medium'
  tag gid: 'V-32263'
  tag rid: 'SV-42580r3_rule'
  tag stig_id: 'IS-16.02.04'
  tag gtitle: 'Controlled Unclassified Information - Encryption of Data at Rest'
  tag fix_id: 'F-36188r5_fix'
  tag 'documentable'
end
