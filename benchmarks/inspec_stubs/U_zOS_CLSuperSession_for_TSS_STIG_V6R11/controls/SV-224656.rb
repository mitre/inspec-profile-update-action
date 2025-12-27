control 'SV-224656' do
  title "CL/SuperSession's Resouce Class is not defined or active in the ACP."
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#RDT)

b)	If the resource class of KLS is defined, there is NO FINDING.

c)	If the resource class of KLS is not defined, this is a FINDING.'
  desc 'fix', 'Add the resource KLS to the TOP SECRET RDT using the following TSS command example:
  
TSS ADD(RDT) RESCLASS(KLS) RESCODE(xx)

(where xx is an unused hex value)'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for TSS'
  tag check_id: 'C-26339r519785_chk'
  tag severity: 'medium'
  tag gid: 'V-224656'
  tag rid: 'SV-224656r519787_rule'
  tag stig_id: 'ZCLST038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26327r519786_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-27190']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
