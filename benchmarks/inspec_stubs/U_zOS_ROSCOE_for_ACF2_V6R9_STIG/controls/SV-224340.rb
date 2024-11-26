control 'SV-224340' do
  title "The ROSCOE's Resource Class is not defined or active in the ACP."
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', "Ensure that the following GSO CLASMAP record entries are defined:

CLASMAPqual RESOURCE(ROSRES) RSRCTYPE(rosid) ENTITYLN(nn)

If all of the items in (b) are true, this is not a finding.

If any item in (b) is untrue, this is a finding.

Note: The site determines the appropriate three letter RSRCTYPE that is unique for each Roscoe system. The ENTITYLN should be appropriate for the site's installation."
  desc 'fix', "Use SAF security to define and protect the Products resource class(es).

Ensure that the following GSO CLASMAP record entry(ies) is (are) defined:

CLASMAP.ROSCOE ENTITYLN(nn) RESOURCE(ROSRES) 
RSRCTYPE(rosid)

Note: The site determines the appropriate three letter RSRCTYPE that is unique for each Roscoe system. The ENTITYLN should be appropriate for the site's installation.

Example:

SET C(GSO)
LIST CLASMAP.ROSCOE
INSERT CLASMAP.ROSCOE ENTITYLN(39) RESOURCE(ROSRES) RSRCTYPE(ROS)

F ACF2,REFRESH(CLASMAP)"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for ACF2'
  tag check_id: 'C-26017r868225_chk'
  tag severity: 'medium'
  tag gid: 'V-224340'
  tag rid: 'SV-224340r868227_rule'
  tag stig_id: 'ZROSA038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26005r868226_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-24845']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
