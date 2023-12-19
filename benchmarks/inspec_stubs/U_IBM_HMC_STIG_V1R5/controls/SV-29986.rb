control 'SV-29986' do
  title 'The Enterprise System Connection (ESCON) Director (ESCD)  Application Console must be located in a secure location'
  desc 'The ESCD Application Console is used to add, change, and delete port configurations and dynamically switch paths between devices. If the ESCON Director Application Console is not located in a secured location, unauthorized personnel can bypass security, access the system, and alter the environment. This could impact the integrity and confidentiality of operations.  NOTE: Many newer installations no longer support the ESCD Application Console.  For installations not supporting the ESCD Application Console, this check is not applicable.'
  desc 'check', 'If the ESCD Application Console is present, verify the location of the ESCD Application Console, otherwise this check is not applicable.

If the ESCON Director Application console is not located in a secure location this is a finding.'
  desc 'fix', "Move the (ESCD) Console Application  console to a secure location and implement access control procedures to ensure access by authorized personnel only.

An ESCD Console Application is used to provide data center personnel with an interface for displaying and
changing an ESCD'S connectivity attributes. It is also used to install, initialize, and service an ESCON Director.
Note: ESCD'S are slowly being phased out and are being replaced with FICON Directors."
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-30356r3_chk'
  tag severity: 'high'
  tag gid: 'V-24340'
  tag rid: 'SV-29986r3_rule'
  tag stig_id: 'HLESC010'
  tag gtitle: 'HLESC010'
  tag fix_id: 'F-27118r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'PECF-1, PECF-2, PEPF-1, PEPF-2'
  tag cci: ['CCI-002101']
  tag nist: ['CA-9 (a)']
end
