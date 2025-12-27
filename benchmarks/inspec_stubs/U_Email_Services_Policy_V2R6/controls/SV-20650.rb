control 'SV-20650' do
  title 'Email Services must be documented in the EDSP (Email Domain Security Plan).'
  desc 'A System Security Plan defines the security procedures and policies applicable to the Automated Information System (AIS). The Email Domain Security Plan (EDSP) defines the security settings and other protections for email systems. It may be implemented as a stand-alone document, or as a section within an umbrella System Security document, provided it contains the unique values engineered for that domain. Without a System Security Plan, unqualified personnel may be assigned responsibilities that they are incapable of meeting and email security may become prone to an inconsistent or incomplete implementation. Because email systems are sufficiently unique, an EDSP is recommended. 

For some email data categories, the product specific STIG provides required security settings. For other categories, values can vary among domains, depending on the implementation and system sizing requirements. For example, tuning variables such as log sizes, mailbox quota limits, and partner domain security are engineered for optimal security and performance, and should therefore be documented so reviews can assess whether they are set as intended. Assigned administrator names by role enable assessment of roles separation and least privilege permissions, as well as the ability to identify unauthorized access of processes or data. Back-up and recovery artifacts, SPAM reputation providers, and anti-virus vendors may differ by domain, and will require operational support information to be recorded, for example, license agreements, product copy locations, and storage requirements. 

NIST publication SP800-18, which is publicly available, is entitled “Guide for Developing Security Plans for Federal Information Systems”. It gives both guidelines and a template for security plan creation, and can serve as a base for development if one is needed. At this writing, the document can be found at the following link: http://csrc.nist.gov/publications/PubsSPs.html. 

Security controls applicable to email systems may not be tracked and followed if they are not identified in the EDSP. Omission of security control consideration could lead to an exploit of email system vulnerabilities or compromise of email information.'
  desc 'check', 'Access the Email Domain Security Plan (EDSP) for email systems. Review for current STIG identification, tuning values, administrator assignments, and procedural IA programs and policies that govern email product servers. 

If email services are not documented in an EDSP, this is a finding.'
  desc 'fix', 'Establish an Email Domain Security Plan (EDSP) to document STIG identification, tuning values, administrator, and procedural IA programs and policies that govern email product servers.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22675r4_chk'
  tag severity: 'medium'
  tag gid: 'V-18867'
  tag rid: 'SV-20650r3_rule'
  tag stig_id: 'EMG3-050 EMail'
  tag gtitle: 'EMG3-050 E-mail System Security Plan'
  tag fix_id: 'F-19571r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'DCSD-1'
end
