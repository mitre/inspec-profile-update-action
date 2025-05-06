control 'SV-209530' do
  title 'The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including transmitted data and data during preparation for transmission.'
  desc 'Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

SSHD should be enabled to facilitate secure remote access.

'
  desc 'check', 'To verify that the installed version of SSH is correct, run the following command:

ssh -V

If the string that is returned does not include "OpenSSH_7.9p1" or greater, this is a finding.

To check if the "SSHD" service is enabled, use the following commands:

/usr/bin/sudo launchctl print-disabled system | grep sshd

If the results do not show "com.openssh.sshd => false", this is a finding.

To check that "SSHD" is currently running, use the following command:

/usr/bin/sudo launchctl print system/com.openssh.sshd

If the result is the following, "Could not find service "com.openssh.sshd" in domain for system", this is a finding.'
  desc 'fix', 'To update SSHD to the minimum required version, run Software Update to update to the latest version of macOS.

To enable the SSHD service, run the following command:

/usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9781r466330_chk'
  tag severity: 'high'
  tag gid: 'V-209530'
  tag rid: 'SV-209530r610285_rule'
  tag stig_id: 'AOSX-14-000011'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-9781r466331_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag legacy: ['SV-104709', 'V-95377']
  tag cci: ['CCI-001453', 'CCI-000068', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'SC-8']
end
