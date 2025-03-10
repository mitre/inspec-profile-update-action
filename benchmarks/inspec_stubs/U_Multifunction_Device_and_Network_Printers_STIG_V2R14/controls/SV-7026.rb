control 'SV-7026' do
  title 'A MFD device, with scan to hard disk functionality used, is not configured to clear the hard disk between jobs.'
  desc 'If the MFD is compromised the un-cleared, previously used, space on the hard disk drive can be read which can lead to a compromise of sensitive data.
The SA will ensure the device is configured to clear the hard disk between jobs if scan to hard disk functionality is used.'
  desc 'check', 'The reviewer, with the assistance of the SA, verify the device is configured to clear the hard disk between jobs if scan to hard disk functionality is used.

Note:  This policy is a security-in-depth measure and applies to normal use. Thus, the clearing algorithm does not have to comply with DoD sanitization procedures. Proper sanitization using a DoD compliant procedure will be required only for final destruction/disposition. 

Note: This does not apply if PKI authenticated access and discretionary access controls (authorization controls) are used to protect the stored data.'
  desc 'fix', 'Configured the MFD to clear the hard disk between jobs if scan to hard disk functionality is used.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3016r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6801'
  tag rid: 'SV-7026r1_rule'
  tag stig_id: 'MFD07.002'
  tag gtitle: 'MFD Clearing Disk Space Scan to Disk'
  tag fix_id: 'F-6475r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECRC-1'
end
