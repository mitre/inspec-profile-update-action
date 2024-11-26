control 'SV-237928' do
  title 'IBM z/VM tapes must use Tape Encryption.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

Guest operating systems, such as CMS, that are not capable of enabling the hardware encryption available with the 3592 Model E05 tape drive are able to use z/VM facilities that enable the encryption on behalf of the guest. Guest operating systems that do support tape encryption, such as z/OS with proper service, will be able to do so without interference from z/VM.'
  desc 'check', 'Verify Tape Encryption is in use.

For IBM drives issue the following command:

Class B:
QUERY TAPES DETAIL

or

Class G:
QUERY VIRTUAL TAPES

If resulting text includes "ACTIVE KEY LABELS", this is not a finding.

Regardless of the drive type if there is no encryption available, this is a finding.'
  desc 'fix', 'Consult CP Administration manual for procedures to set up IBM Device Encryption.

For any other drive type consult manufacturer for encryption procedures.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41138r858990_chk'
  tag severity: 'medium'
  tag gid: 'V-237928'
  tag rid: 'SV-237928r858991_rule'
  tag stig_id: 'IBMZ-VM-000750'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-41097r649623_fix'
  tag 'documentable'
  tag legacy: ['SV-93609', 'V-78903']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
