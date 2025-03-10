control 'SV-224499' do
  title 'External RACF Classes are not active for CICS transaction checking.'
  desc 'Implement CICS transaction security by utilizing two distinct and unique RACF resource
classes (i.e., member and grouping) within each CICS region. If several CICS regions are
grouped in an MRO environment, it is permissible for those grouped regions to share a
common pair of resource classes. Member classes contain a RACF discrete profile for
each transaction. Grouping classes contain groups of transactions requiring equal
protection under RACF. Ideally, member classes contain no profiles, and all transactions
are defined by groups in a grouping class.

If CICS Classes are not active, this could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure each CICS transaction resource class pair are active.

c)	If (b) is true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'Review each CICS SIT to ensure each region has a unique resource class or resource prefix specified. 

1.  The resources classes are activated in RACF using the following command:  SETR CLASSACT(<classname>)'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26182r520283_chk'
  tag severity: 'medium'
  tag gid: 'V-224499'
  tag rid: 'SV-224499r520285_rule'
  tag stig_id: 'ZCICR038'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26170r520284_fix'
  tag 'documentable'
  tag legacy: ['SV-301', 'V-301']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
