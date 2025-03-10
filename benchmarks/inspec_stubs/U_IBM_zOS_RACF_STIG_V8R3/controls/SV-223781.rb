control 'SV-223781' do
  title 'Unsupported system software must not be installed and/ or active on the system.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'This check applies to all products that meet the following criteria:

- Uses authorized and restricted z/OS interfaces by utilizing Authorized Program Facility (APF) authorized modules or libraries.
- Require access to system datasets or sensitive information or requires special or privileged authority to run.

For the products in the above category refer to the Vendor’s support lifecycle information for current versions and releases. 

If the software products currently running on the reviewed system are at a version greater than or equal to the products listed in the vendor’s Support Lifecycle information, this is not a finding.'
  desc 'fix', 'For all products that meet the following criteria:

- Uses authorized and restricted z/OS interfaces by utilizing Authorized Program Facility (APF) authorized modules or libraries.
- Require access to system datasets or sensitive information or requires special or privileged authority to run.

The ISSO will ensure that unsupported system software for the products in the above category is removed or upgraded prior to a vendor dropping support.

Authorized software which is NO longer supported is a CAT I – vulnerability. The customer and site will be given 6 months to mitigate the risk, come up with a supported solution, or obtain a formal letter approving such risk/software.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25454r515031_chk'
  tag severity: 'high'
  tag gid: 'V-223781'
  tag rid: 'SV-223781r604139_rule'
  tag stig_id: 'RACF-OS-000250'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25442r515032_fix'
  tag 'documentable'
  tag legacy: ['V-98269', 'SV-107373']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
