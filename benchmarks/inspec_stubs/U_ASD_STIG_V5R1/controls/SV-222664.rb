control 'SV-222664' do
  title 'If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.'
  desc 'Without a classification guide the marking, storage, and output media of classified material can be inadvertently mixed with unclassified material, leading to its possible loss or compromise.'
  desc 'check', 'If the application does not process classified information, this check is not applicable.
 
The application may already be covered by a higher level program or other classification guide. If the classification guide is not written specifically to the application, the sensitive application data should be reviewed to determine whether it is contained in the classification guide.

DoD 5200.01R identifies requirements for security classification and/or declassification guides.

http://www.dtic.mil/whs/directives/corres/pdf/520001_vol1.pdf

Security classification guides shall provide the following information:

Identify specific items, elements, or categories of information to be protected.

State the specific classification to be assigned to each item or element of information and, when useful, specify items of information that are unclassified.

Provide declassification instructions for each item or element of information, to include the applicable exemption category for information exempted from automatic declassification.

State a concise reason for classification for each item, element, or category of information that, at a minimum, cites the applicable classification categories in Section 1.5 of E.O. 12958.

Identify any special handling caveats that apply to items, elements, or categories of information.

Identify, by name or personal identifier and position title, the original classification authority approving the guide and the date of that approval.

Provide a point-of-contact for questions about the guide and suggestions for improvement.

For information exempted from automatic declassification because its disclosure would reveal foreign government information or violate a statute, treaty, or international agreement, the security classification guide will identify the government or specify the applicable statute, treaty, or international agreement, as appropriate.

If the security classification guide does not exist, or does not contain application data elements and their classification, this is a finding.'
  desc 'fix', 'Create and maintain a security classification guide.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24334r493900_chk'
  tag severity: 'medium'
  tag gid: 'V-222664'
  tag rid: 'SV-222664r508029_rule'
  tag stig_id: 'APSC-DV-003290'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24323r493901_fix'
  tag 'documentable'
  tag legacy: ['V-70407', 'SV-85029']
  tag cci: ['CCI-000366', 'CCI-003124']
  tag nist: ['CM-6 b', 'SA-5 a 1']
end
