control 'SV-225603' do
  title 'ROSCOE is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for the Product could result in the compromise of the network, operating system, and customer data.

*****This vulnerability only applies to Top Secret started tasks. *****'
  desc 'check', 'a)	Refer to the following reports produced by the TSS Data Collection:

-	TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values.
-	TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup.

NOTE:	The FACLIST report must be created by DECC security personnel.  The TSSPRMFL report can be used if DECC security personnel have not executed the required steps documented in the TSS Data Collection.

b)	Review the FACLIST report.  Ensure the Product Facility is properly defined as specified by the product system programmer.

c)	If the Product facility control options are defined as indicated by the product system programmer, there is NO FINDING.

d)	If any of the Product facility control options are not defined as indicated by the product system programmer , this is a FINDING.'
  desc 'fix', 'The Facility ROSCOE comes predefined with CA-TSS.  Please ensure you add the following to your TSS parmlib for the FAC(ROSCOE):

****
****   ROSCOE                                                          *
****
FACILITY(ROSCOE=NOLUMSG,NORNDPW)'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for TSS'
  tag check_id: 'C-27303r520868_chk'
  tag severity: 'medium'
  tag gid: 'V-225603'
  tag rid: 'SV-225603r520870_rule'
  tag stig_id: 'ZROST036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27291r520869_fix'
  tag 'documentable'
  tag legacy: ['SV-24943', 'V-17469']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
