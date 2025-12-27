control 'SV-239188' do
  title 'The Photon operating system must enforce password complexity on the root account.'
  desc 'Password complexity rules must apply to all accounts on the system, including root. Without specifying the enforce_for_root flag, pam_cracklib does not apply complexity rules to the root user. While root users can find ways around this requirement, given its superuser power, it is necessary to attempt to force compliance.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always "enforce_for_root"

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding.

NOTE: After the fix is implemented, the check will not pass until either a reboot is performed or both files are modified, which happens automatically on reboot.'
  desc 'fix', 'Open /etc/applmgmt/appliance/system-password with a text editor.

Comment out any existing "pam_cracklib.so" line and add the following:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Save and close.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42399r863034_chk'
  tag severity: 'medium'
  tag gid: 'V-239188'
  tag rid: 'SV-239188r863035_rule'
  tag stig_id: 'PHTN-67-000117'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42358r816675_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
