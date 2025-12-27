control 'SV-99203' do
  title 'The SMTP service must not have the VRFY feature active.'
  desc 'The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Use the following command to check if VRFY is disabled:

# grep -v "^#" /etc/sendmail.cf |grep -i PrivacyOptions

If "novrfy" is not returned, this is a finding.'
  desc 'fix', 'Add "novrfy" to the "PrivacyOptions" flag in the "/etc/sendmail.cf" file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88245r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88553'
  tag rid: 'SV-99203r1_rule'
  tag stig_id: 'VROM-SL-000610'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95295r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
