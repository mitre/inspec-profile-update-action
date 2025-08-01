control 'SV-90647' do
  title 'The OS X system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including transmitted data and data during preparation for transmission.'
  desc 'Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'For systems that allow remote access through SSH, run the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd

If the results do not show the following, this is a finding.

"com.openssh.sshd" => false'
  desc 'fix', 'To enable the SSH service, run the following command:

/usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75643r1_chk'
  tag severity: 'high'
  tag gid: 'V-75959'
  tag rid: 'SV-90647r1_rule'
  tag stig_id: 'AOSX-12-000035'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-82597r1_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
