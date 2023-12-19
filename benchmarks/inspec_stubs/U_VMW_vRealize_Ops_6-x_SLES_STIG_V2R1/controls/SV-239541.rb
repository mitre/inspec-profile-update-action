control 'SV-239541' do
  title 'The SMTP service must not have the VRFY feature active.'
  desc 'The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Use the following command to check if VRFY is disabled:

# grep -v "^#" /etc/sendmail.cf |grep -i PrivacyOptions

If "novrfy" is not returned, this is a finding.'
  desc 'fix', 'Add "novrfy" to the "PrivacyOptions" flag in the "/etc/sendmail.cf" file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42774r662072_chk'
  tag severity: 'medium'
  tag gid: 'V-239541'
  tag rid: 'SV-239541r662074_rule'
  tag stig_id: 'VROM-SL-000610'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42733r662073_fix'
  tag 'documentable'
  tag legacy: ['SV-99203', 'V-88553']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
