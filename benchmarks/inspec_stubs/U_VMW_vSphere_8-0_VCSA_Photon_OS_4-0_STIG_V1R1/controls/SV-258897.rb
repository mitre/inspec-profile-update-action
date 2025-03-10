control 'SV-258897' do
  title 'The Photon operating system must enforce password complexity on the root account.'
  desc 'Password complexity rules must apply to all accounts on the system, including root. Without specifying the enforce_for_root flag, pam_pwquality does not apply complexity rules to the root user. While root users can find ways around this requirement, given its superuser power, it is necessary to attempt to force compliance.'
  desc 'check', %q(At the command line, run the following command to verify password complexity is enforced for the root account:

# grep '^password.*pam_pwquality.so' /etc/pam.d/system-password

Example result:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

If the "enforce_for_root" option is missing or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Configure the pam_pwquality.so line to have the "enforce_for_root" option present as follows:

password  requisite   pam_pwquality.so  dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=15 difok=8 enforce_for_root dictcheck=1

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62637r933750_chk'
  tag severity: 'medium'
  tag gid: 'V-258897'
  tag rid: 'SV-258897r933752_rule'
  tag stig_id: 'PHTN-40-000235'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62546r933751_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
