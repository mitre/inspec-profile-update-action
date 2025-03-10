control 'SV-224737' do
  title 'Control options for the Top Secret CICS facilities must meet minimum requirements.'
  desc 'TSS CICS facilities define the security controls in effect for CICS regions. Failure to code the appropriate values could result in degraded security. This exposure may result in unauthorized access impacting the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', "a) Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the following reports produced by the TSS Data Collection:

- TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
- TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b) Ensure the following items are in effect for each CICS region's facility:

1) The TSS CICS facility is defined with the control option values specified in the TOP SECRET INITIALIZATION PARAMETERS FOR CICS REGION Table in the z/OS STIG Addendum .

Note: An exception to the STIG is MRO CICS regions in production will use SIGN(M) appropriately.

2) XUSER=YES must be coded in each CICS facility.
3) CICS transactions defined in the BYPASS list are not sensitive transactions.

c) If the items in (b) are true for all CICS region's facility, there is no finding.

d) If any item in (b) is untrue for a CICS region's facility, this is a finding."
  desc 'fix', %q(Review the TSS control option values for all CICS facilities.
Ensure the following items are in effect for each CICS region's facility: 

1) The TSS CICS facility is defined with the control option values specified in table - "TOP SECRET INITIALIZATION PARAMETERS FOR CICS REGION" , in the zOS STIG Addendum. Note: An exception is MRO CICS regions in production will use SIGN(M) appropriately. 
2) XUSER=YES must be coded in each CICS facility. 
3) CICS transactions defined in the BYPASS list are not sensitive transactions.)
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for TSS'
  tag check_id: 'C-26428r868637_chk'
  tag severity: 'medium'
  tag gid: 'V-224737'
  tag rid: 'SV-224737r868639_rule'
  tag stig_id: 'ZCICT050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-26416r868638_fix'
  tag 'documentable'
  tag legacy: ['SV-8032', 'V-7555']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
