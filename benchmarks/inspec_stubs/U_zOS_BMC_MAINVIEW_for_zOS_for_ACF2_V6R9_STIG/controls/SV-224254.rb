control 'SV-224254' do
  title 'BMC Mainview for z/OS Resource Class will be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'If the following GSO CLASMAP record entries are defined this is not a finding.

CLASMAP.class RESOURCE(class) RSRCTYPE(type) ENTITYLN(nn)

Note:  The site determines the appropriate three letter RSRCTYPE that is unique for Mainview. The ENTITYLN should be appropriate for the site’s installation. 	

If the following GSO SAFDEF record entries are defined this not a finding.

INSERT SAFDEF.ssid ID(BBCS) MODE(GLOBAL)REP -
RACROUTE(SUBSYS=ssid REQSTOR=-)'
  desc 'fix', 'Use SAF security to define and protect the Products resouceresource class(es).

Ensure that the following GSO CLASMAP record entry(ies) is (are) defined:

CLASMAP.class RESOURCE(class) RSRCTYPE(type) ENTITYLN(nn)

Note:  The site determines the appropriate three letter RSRCTYPE that is unique for Mainview. The ENTITYLN should be appropriate for the site’s installation. 

Example:

SET C(GSO)
LIST CLASMAP.BMCVIEW
INSERT CLASMAP.BMCVIEW ENTITYLN(39) RESOURCE(BMCVIEW) RSRCTYPE(BBM)

F ACF2,REFRESH(CLASMAP)

Ensure that the following GSO SAFDEF record entry(ies) is (are) defined:

SAFDEF.ssid ID(BBCS) MODE(GLOBAL)REP RACROUTE(SUBSYS=ssid REQSTOR=-)

Example:

ACF
SET C(GSO)
LIST SAFDEF.ssid
INSERT SAFDEF.ssid ID(BBCS) MODE(GLOBAL)REP RACROUTE(SUBSYS=ssid REQSTOR=-)

F ACF2,REFRESH(SAFDEF)'
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for ACF2'
  tag check_id: 'C-25927r822580_chk'
  tag severity: 'medium'
  tag gid: 'V-224254'
  tag rid: 'SV-224254r822582_rule'
  tag stig_id: 'ZMVZA038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-25915r822581_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-33844']
  tag cci: ['CCI-002358', 'CCI-000336']
  tag nist: ['AC-25', 'CM-4 (2)']
end
