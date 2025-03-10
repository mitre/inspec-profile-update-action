control 'SV-252883' do
  title 'IBM Integrated Crypto Service Facility (ICSF) install data sets must be properly protected.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'If the ESM dataset rules for the  IBM Integrated Crypto Service Facility (ICSF) install data sets  does not restrict UPDATE and/or ALTER access to systems programming personnel this is a finding.

If the ESM  data set rules for  IBM Integrated Crypto Service Facility (ICSF) install data set does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged this is a finding.'
  desc 'fix', 'Ensure that update and allocate access to IBM Integrated Crypto Service Facility (ICSF) install data sets is limited to System Programmers only, and all update and allocate access is logged. Read access can be given to Auditors and any other users that have a valid requirement to utilize these data sets.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.  He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS1.CSF

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS1)
CSF.- UID(syspaudt) R(A) W(L) A(L) E(A)
CSF.- UID(tstcaudt) R(A) W(L) A(L) E(A)
CSF.- UID(icsfusrs) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-56339r822536_chk'
  tag severity: 'medium'
  tag gid: 'V-252883'
  tag rid: 'SV-252883r822538_rule'
  tag stig_id: 'ACF2-IC-000020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-56289r822537_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-30547']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
