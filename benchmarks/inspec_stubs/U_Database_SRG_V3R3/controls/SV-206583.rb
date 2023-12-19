control 'SV-206583' do
  title 'The DBMS must associate organization-defined types of security labels having organization-defined security label values with information in process.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of the DBMS product, a third-party product, or custom application code.'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in process, this is a finding.'
  desc 'fix', 'Enable DBMS features, deploy third-party software, or add custom data structures, data elements and application code, to provide reliable security labeling of information in process.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6843r291417_chk'
  tag severity: 'medium'
  tag gid: 'V-206583'
  tag rid: 'SV-206583r617447_rule'
  tag stig_id: 'SRG-APP-000313-DB-000309'
  tag gtitle: 'SRG-APP-000313'
  tag fix_id: 'F-6843r291418_fix'
  tag 'documentable'
  tag legacy: ['SV-72469', 'V-58039']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
