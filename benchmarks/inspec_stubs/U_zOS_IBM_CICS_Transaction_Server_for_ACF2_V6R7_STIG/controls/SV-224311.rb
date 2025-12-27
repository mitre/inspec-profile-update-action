control 'SV-224311' do
  title 'Key ACF2/CICS parameters must be properly coded.'
  desc 'The ACF2/CICS parameters define the security controls in effect for CICS regions. Failure to code the appropriate values could result in degraded security. This exposure may result in unauthorized access impacting the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a) Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

Refer to the CICS region SYSLOG - (Alternate source of SIT parameters)

b) Browse the ACF2/CICS data set allocated by the ACF2PARM DD statement in the JCL of each CICS procedure.

c) If all key ACF2/CICS parameters for every CICS region are coded as stated in the table entitled ACF2/CICS Parameters in the z/OS STIG Addendum, this is not a finding.

Note: The DEFAULT TERMINAL=parameter must be specified.
CICSKEY OPTION=VALIDATE,TYPE=resource type,RESOURCE=TRANS will specify a unique resource type for each CICS region.

d) If any key ACF2/CICS parameter is not coded as referenced in (c), this is a finding.'
  desc 'fix', 'Ensure the ACF2/CICS parameters are coded with values specified in the table entitled ACF2/CICS Parameters, in the zOS STIG Addendum.

Browse the ACF2/CICS data set allocated by the ACF2PARM DD statement in the JCL of each CICS procedure.

Ensure that all key ACF2/CICS parameters for every CICS region are coded as stated in the table entitled ACF2/CICS Parameters, in the zOS STIG Addendum.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25988r868104_chk'
  tag severity: 'medium'
  tag gid: 'V-224311'
  tag rid: 'SV-224311r868106_rule'
  tag stig_id: 'ZCICA023'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-25976r868105_fix'
  tag 'documentable'
  tag legacy: ['SV-8031', 'V-7554']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
