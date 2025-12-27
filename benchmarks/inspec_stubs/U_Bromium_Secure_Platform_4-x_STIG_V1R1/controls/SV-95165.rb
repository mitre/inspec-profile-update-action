control 'SV-95165' do
  title 'The Bromium vSentry client must prohibit user installation of software except for clients that are explicitly approved by the ISSM or other authorizing official.'
  desc 'Allowing regular users to install software without explicit privileges creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository. 

The application must enforce software installation by users based on what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.'
  desc 'check', 'Inspect the base and delta policy on the Bromium Enterprise Controller (BEC) that is responsible for the analysis of executables.

1. From the management console, navigate to "Policies".
2. Inspect the base and all delta policy used for analyzing executables (e.g., "SOC Mode").
3. Verify parameter "mimehandler.executable.open" has a value of "1".
4. Verify parameter "LAVA.ExecutableVMVisible" has a value of "0".
5. Verify parameter "LAVA.ExecutableVMTime" has a value (in seconds) for the desired time that the executable should run for the purposes of analysis (e.g., "300").
6. For clients that are allowed to install software, verify a separate delta policy exists for these clients. This will override the base policy for these specific devices only (e.g., management workstations use by the system administrators).

If Bromium vSentry does not prohibit user installation of software without explicit privileged status, this is a finding.'
  desc 'fix', %q(Isolate the execution and installation of untrusted and unauthorized applications within a micro-virtual machine (VM):

1. From the management console, navigate to "Policies".
2. Create or modify a base and/or delta policy used for analyzing executables (e.g., "SOC Mode").
3. Add parameter "mimehandler.executable.open" with a value of "1" to enable the isolation of untrusted executables.
4. Add parameter "LAVA.ExecutableVMVisible" with a value of "0" to conceal the untrusted executable from the user's view.
5. Add parameter "LAVA.ExecutableVMTime" with a value (in seconds) for the desired time that the executable should run for the purposes of analysis (e.g., "300").
6. For clients that are allowed to install software, verify a separate delta policy exists for these clients. This will override the base policy for these specific devices only (e.g., management workstations use by the system administrators).)
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80461'
  tag rid: 'SV-95165r1_rule'
  tag stig_id: 'BROM-00-000865'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-87267r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
