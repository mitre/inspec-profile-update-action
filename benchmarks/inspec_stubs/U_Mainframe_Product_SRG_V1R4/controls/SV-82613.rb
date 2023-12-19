control 'SV-82613' do
  title 'The Mainframe Product must associate types of security attributes having security attribute values as defined in site security plan with information in storage.'
  desc 'Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.

Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in storage. If the security attributes are lost when the data is stored, there is the risk of a data compromise.'
  desc 'check', 'If the Mainframe Product does not perform data management or storage function this is not applicable.

Examine installation and configuration settings and / or specific meta-data for security attributes as defined by the organization. 

If there is no data labeling or tagging, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to associate organization-defined security attributes to managed data sets in storage.

Verify the datasets attributes are labeled and/or tagged appropriately.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68123'
  tag rid: 'SV-82613r1_rule'
  tag stig_id: 'SRG-APP-000311-MFP-000025'
  tag gtitle: 'SRG-APP-000311-MFP-000025'
  tag fix_id: 'F-74239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']
end
