control 'SV-224322' do
  title 'IBM System Display and Search Facility (SDSF) Resource Class will be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', "Refer to the following report produced by the ACF2 Data Collection:

- ACF2CMDS.RPT(ACFGSO)

If the following GSO CLASMAP record entry(ies) is (are) defined, this is not a finding.

CLASMAP.SDSF RESOURCE(SDSF) RSRCTYPE(xxx) ENTITYLN(nn)

Note: The site determines the appropriate three-letter RSRCTYPE that is unique for the SDSF. The ENTITYLN must be appropriate for the site's installation."
  desc 'fix', 'Use SAF security to define and protect the IBM SDSF resource class(es).

Use the following commands as an example:

CLASMAP.SDSF RESOURCE(SDSF) RSRCTYPE(SDF) ENTITYLN(39)'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for ACF2'
  tag check_id: 'C-25999r868187_chk'
  tag severity: 'medium'
  tag gid: 'V-224322'
  tag rid: 'SV-224322r868188_rule'
  tag stig_id: 'ZISFA038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-25987r822587_fix'
  tag 'documentable'
  tag legacy: ['SV-40830', 'V-18011']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
