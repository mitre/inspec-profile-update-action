control 'SV-7030' do
  title 'A MFD device does not have a mechanism to lock and prevent access to the hard drive.'
  desc 'If the hard disk drive of a MFD can be removed from the MFD the data on the drive can be recovered and read.  This can lead to a compromise of sensitive data.

The IAO will ensure the device has a mechanism to lock and prevent access to the hard disk.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that the device has a mechanism to lock and prevent access to the hard disk.

What we are looking for here is a locking mechanism with a key securing the hard drive or the case access to the hard drive.  The lock will be locked or this is a finding.

Note:  This is not required if physical security measures are in place, if the drive is not easily removable, if drive is encrypted, or if there is zeroization or other strong protection mechanism.'
  desc 'fix', 'If the lock is not locked, lock it.

If there is no lock see if the vendor makes one and if so acquire it an lock the drive.
If the vendor does not supply a lock, acquire an aftermarket lock that will secure the drive so that it cannot be accessed.  Even a drive that cannot be removed but the connectors can be removed is vulnerable.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3020r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6805'
  tag rid: 'SV-7030r1_rule'
  tag stig_id: 'MFD08.001'
  tag gtitle: 'MFD Hard Drive Lock'
  tag fix_id: 'F-6479r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'PECF-1, PECF-2'
end
