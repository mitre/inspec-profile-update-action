control 'SV-29469' do
  title 'An approved, up-to-date, DoD antivirus program must be installed and used.'
  desc 'Antivirus programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing an antivirus program provides the ability to detect malicious code before extensive damage occurs.  Updated virus scan data files help to protect a system, since new malware are identified by the software vendors on a continual basis.'
  desc 'check', 'If V-19910 from an antivirus STIG has been applied to the system, the signature verification portion of this requirement is NA.

Verify a supported DoD antivirus product has been installed on the system.

If McAfee VirusScan Enterprise 8.8 or later is not installed on the system, this is a finding.

And

If a product other than McAfee VirusScan Enterprise is used and V-19910 from an antivirus STIG has not been applied to the system, verify the date of the antivirus signature. 

If the antivirus program signature has not been updated within the past 7 days, this is a finding.

The version numbers and the date of the signature can generally be checked by starting the antivirus program.  The information may appear in the antivirus window or be available in the Help >> About window.  The location varies from product to product.'
  desc 'fix', 'Install McAfee VirusScan Enterprise 8.8 or later on the system.  Update the signature file at least every 7 days.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-61983r2_chk'
  tag severity: 'high'
  tag gid: 'V-1074'
  tag rid: 'SV-29469r3_rule'
  tag gtitle: 'WIN00-000100'
  tag fix_id: 'F-66879r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If another recognized antivirus product is installed and has a current signature, this would still be a finding; however, the severity may be reduced to a CAT III.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
