control 'SV-258853' do
  title 'The Photon operating system must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', %q(At the command line, run the following command to verify passwords do not match dictionary words:

# grep '^password.*pam_pwquality.so' /etc/pam.d/system-password

Example result:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

If the "dictcheck" option is not set to 1, is missing or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Configure the pam_pwquality.so line to have the "dictcheck" option set to "1" as follows:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62593r933618_chk'
  tag severity: 'medium'
  tag gid: 'V-258853'
  tag rid: 'SV-258853r933620_rule'
  tag stig_id: 'PHTN-40-000184'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-62502r933619_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
