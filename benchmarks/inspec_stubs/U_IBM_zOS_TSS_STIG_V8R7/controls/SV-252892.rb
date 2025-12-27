control 'SV-252892' do
  title 'IBM Integrated Crypto Service Facility (ICSF) install data sets are not properly protected.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Verify that access to the IBM IntegrTated Crypto Service Facility (ICSF) install data sets are properly restricted.

Execute a data set list of access to the IBM Integrated Crypto Service Facility (ICSF) install data sets
 
If the TSS data set rules for the data sets does not restrict UPDATE and/or ALL access to systems programming personnel this is a finding.

If the TSS data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALL access will be logged this is a finding.'
  desc 'fix', 'Ensure that update and allocate access to IBM Integrated Crypto Service Facility (ICSF) install data sets is limited to System Programmers only, and all update and allocate access is logged. Read access can be given to Auditors and any other users that have a valid requirement to utilize these data sets.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.  He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS1.CSF

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(syspaudt) DSN(SYS1.CSF.) ACCESS(R)
TSS PERMIT(tstcaudt) DSN(SYS1.CSF.) ACCESS(R)
TSS PERMIT(icsfusrs) DSN(SYS1.CSF.) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS1.CSF.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(tstcaudt) DSN(SYS1.CSF.) ACCESS(ALL) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-56348r822563_chk'
  tag severity: 'medium'
  tag gid: 'V-252892'
  tag rid: 'SV-252892r864496_rule'
  tag stig_id: 'TSS0-IC-000020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-56298r822564_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-30550']
  tag cci: ['CCI-000213', 'CCI-002264']
  tag nist: ['AC-3', 'AC-16 a']
end
