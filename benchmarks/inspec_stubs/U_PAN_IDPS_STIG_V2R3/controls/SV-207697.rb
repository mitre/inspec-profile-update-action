control 'SV-207697' do
  title 'The Palo Alto Networks security platform must automatically install updates to signature definitions, detection heuristics, and vendor-provided rules.'
  desc "Failing to automatically update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. An automatic update process ensures this important task is performed without the need for SCA intervention.

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be automatically updated, including anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

If a DoD patch management server or update repository having the tested/verified updates is available for the device component, the components must be configured to automatically check this server/site for updates and install new updates.

If a DoD server/site is not available, the component must be configured to automatically check a trusted vendor site for updates. A trusted vendor is either commonly used by DoD, specifically approved by DoD, the vendor from which the equipment was purchased, or approved by the local program's CCB."
  desc 'check', 'To verify that automatic updates are configured:
Go to Device >> Dynamic Updates

If no entries for "Applications and Threats" are present, this is a finding.

If the "Applications and Threats" entry states "Download Only", this is a finding.'
  desc 'fix', 'Go to Device >> Dynamic Updates
Select "Check Now" at the bottom of the page to retrieve the latest signatures.
To schedule automatic signature updates.  
Note: the steps provided below do not account for local change management policies.

Go to Device >> Dynamic Updates
Select the text to the right of "Schedule".
In the "Applications and Threat Updates Schedule" Window; complete the required information.  
In the "Recurrence" field, select "Daily".
In the "Time" field, enter the time at which you want the device to check for updates.
For the "Action", select "Download and Install".   
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7951r358424_chk'
  tag severity: 'medium'
  tag gid: 'V-207697'
  tag rid: 'SV-207697r557390_rule'
  tag stig_id: 'PANW-IP-000029'
  tag gtitle: 'SRG-NET-000251-IDPS-00178'
  tag fix_id: 'F-7951r358425_fix'
  tag 'documentable'
  tag legacy: ['SV-77155', 'V-62665']
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
