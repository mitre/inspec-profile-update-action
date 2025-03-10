control 'SV-223661' do
  title 'IBM RACF started tasks defined with the trusted attribute must be justified.'
  desc 'Trusted Started tasks bypass RACF checking. It is vital that this attribute is NOT granted to unauthorized Started Tasks which could then obtain unauthorized access to the system. This could result in the compromise of the confidentiality, integrity, and availability of the operating system, ACP, or customer data.'
  desc 'check', 'Refer to the list of z/OS started tasks and address spaces in the IBM z/OS MVS Initialization and Tuning Reference. 

If the only approved Started Tasks that have the TRUSTED flag enabled are in this list, this is not a finding. 

If there are no Started Tasks that have been granted the PRIVILEGED attribute, this is not a finding.

Guidelines for reference:

Assign the TRUSTED attribute when one of the following conditions applies:
- The started procedure or address space creates or accesses a wide variety of unpredictably named data sets within your installation.
- Insufficient authority to an accessed resource might risk an unsuccessful IPL or other system problem.
Avoid assigning TRUSTED to a z/OS started procedure or address space unless it is listed here or you are instructed to do so by the product documentation.

Additionally external security managers are candidates for trusted attribute. 
Any other started tasks not listed or not covered by the guidelines are a finding unless approval by the Authorizing Official.'
  desc 'fix', 'Review assignment of the TRUSTED attribute in ICHRIN03 and/or the STARTED resource class. Ensure only those trusted STCs that are listed in the IBM z/OS MVS Initialization and Tuning Reference have been granted this authority. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes. While the actual list may vary based on local site requirements and software configuration, the started tasks listed in the IBM z/OS MVS Initialization and Tuning Reference is an approved list of started tasks that may be considered trusted started procedures. Guidelines for reference:

Assign the TRUSTED attribute when one of the following conditions applies:
-The started procedure or address space creates or accesses a wide variety of unpredictably named data sets within your installation.
-Insufficient authority to an accessed resource might risk an unsuccessful IPL or other system problem.
-Avoid assigning TRUSTED to a z/OS started procedure or address space unless it is listed here or you are instructed to do so by the product documentation.

Additionally external security managers are candidates for trusted attribute. Any other started tasks not listed or not covered by the guidelines are a finding unless approval by the Authorizing Official.

The TRUSTED attribute can be removed from a STARTED class profile using the command:
RALT STARTED <profilename> STDATA(TRUSTED(NO))

If the STARTED class is RACLISTed then a refresh command is necessary:
SETR RACL(STARTED) REFRESH

If any Started Tasks exist with the PRIVILEGED attribute then take the following action to remove this attribute:
RALT STARTED <profilename> STDATA(PRIVILEGED(NO))

If the STARTED class is RACLISTed then a refresh command is necessary:
SETR RACL(STARTED) REFRESH'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25334r514672_chk'
  tag severity: 'medium'
  tag gid: 'V-223661'
  tag rid: 'SV-223661r604139_rule'
  tag stig_id: 'RACF-ES-000130'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25322r514673_fix'
  tag 'documentable'
  tag legacy: ['V-98027', 'SV-107131']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
