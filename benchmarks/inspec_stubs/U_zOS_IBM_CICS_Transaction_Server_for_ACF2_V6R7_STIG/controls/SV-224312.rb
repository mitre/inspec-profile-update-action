control 'SV-224312' do
  title 'Sensitive CICS transactions are not protected in accordance with the proper security requirements.'
  desc 'Sensitive CICS transactions offer the ability to circumvent transaction level controls for accessing resources under CICS.  These transactions must be protected so that only authorized users can access them.  Unauthorized use can result in the compromise of the confidentiality, integrity, and availability of the operating system or customer data.'
  desc 'check', 'a) Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b) Browse the ACF2/CICS data set allocated by the ACF2PARM DD statement in the JCL of each CICS procedure.

c) Ensure the following items are in effect for entries specified in the SAFELIST parameter:

1) Transactions are uniquely identified.
2) Transactions are not masked.
3) Sensitive transactions are not included.

NOTE:  For information on transactions that are eligible for exemption from security checking refer to Category 3 Transactions for CICS TS 3.1 - 5.1 in the z/OS STIG addendum.
d) If the items in (c) are true for all entries specified in the SAFELIST parameter for each CICS region, there is no finding.

e) If any item in (c) is untrue for any entry specified in the SAFELIST parameter, this is a finding.'
  desc 'fix', 'The Systems Programmer and IAO will ensure the ACF2/CICS parameter SAFELIST are coded with the values specified below.

Browse the ACF2/CICS data set allocated by the ACF2PARM DD statement in the JCL of each CICS procedure.

Ensure the following items are in effect for entries specified in the SAFELIST parameter: 

1) Transactions are uniquely identified.
2) Transactions are not masked.
3) Sensitive transactions are not included.

NOTE:  For information on transactions that are eligible for exemption from security checking refer to Category 3 Transactions for CICS TS 3.1 - 5.1 in the z/OS STIG addendum.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25989r520256_chk'
  tag severity: 'medium'
  tag gid: 'V-224312'
  tag rid: 'SV-224312r520258_rule'
  tag stig_id: 'ZCICA024'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-25977r520257_fix'
  tag 'documentable'
  tag legacy: ['SV-7189', 'V-6894']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
