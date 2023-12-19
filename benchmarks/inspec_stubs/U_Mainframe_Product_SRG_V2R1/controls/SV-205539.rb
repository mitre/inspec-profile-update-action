control 'SV-205539' do
  title 'The Mainframe Product must associate types of security attributes having security attribute values as defined in site security plan with information in process.'
  desc 'Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.

Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in process. If the security attributes are lost when the data is being processed, there is the risk of a data compromise.'
  desc 'check', 'If the Mainframe Product does not perform data management or storage function this is not applicable.

Examine installation and configuration settings and / or specific meta-data for individual types of security attributes as defined by the organization. 

If there is no specific data labeling or tagging, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to associate organization-defined security attributes to managed data sets in process.

Verify the datasets attributes are labeled and/or tagged appropriately.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5805r299850_chk'
  tag severity: 'medium'
  tag gid: 'V-205539'
  tag rid: 'SV-205539r851307_rule'
  tag stig_id: 'SRG-APP-000313-MFP-000026'
  tag gtitle: 'SRG-APP-000313'
  tag fix_id: 'F-5805r299851_fix'
  tag 'documentable'
  tag legacy: ['SV-82615', 'V-68125']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
