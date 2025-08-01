control 'SV-43023' do
  title 'A security risk analysis must be performed on a mobile application by the Authorizing Official (AO) or AO-authorized authority prior to the application being approved for use.'
  desc 'Non-approved applications can contain malware. Approved applications should be reviewed and tested by the AO to ensure they do not contain malware, spyware, or have unexpected features (e.g., send private information to a web site, track user actions, and connect to a non-DoD management server).'
  desc 'check', 'Detailed Requirements:
Core applications are applications included in the mobile device operating system. Applications added by the device vendor and wireless carrier are not considered core applications. A security risk analysis must be performed by the AO or AO-approved approval authority prior to a mobile application being approved for use.

- The application review and approval process must include an evaluation of what OS level permissions are required by the application and how the application shares data and memory space with other applications. The review process must also ensure approved applications do not contain malware or share data stored on the mobile OS device with non-DoD servers.

Check Procedures:



Ask the site for documentation showing what security risk analysis procedures are used by the AO prior to approving non-core applications for use.

Determine if the procedures include an evaluation of the following:
- What OS level permissions are required by the application? 
- The application does not contain malware.
- The application does not share data stored on the CMDs with non-DoD servers.
- If the application stores sensitive data, the application data storage container uses FIPS 140-2 validated cryptographic module.

If a security review was not conducted on approved applications or the application security risk review procedures do not contain the required risk assessment evaluation tasks, this is a finding.'
  desc 'fix', 'Have AO or Command IT CCB use the required procedures to review mobile applications prior to approving them.'
  impact 0.7
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-41050r10_chk'
  tag severity: 'high'
  tag gid: 'V-32677'
  tag rid: 'SV-43023r5_rule'
  tag stig_id: 'WIR-SPP-021'
  tag gtitle: 'Mobile application security review'
  tag fix_id: 'F-36582r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
